/**
 * Asset channel state in the channel row (issue #2093, step 5).
 *
 * Two promises are held here. A channel without asset state is stored as
 * the bytes it always was, in its row and in every recovery frame that
 * carries it: the digests below were taken from the code before asset
 * channels touched the storage codec. And a channel with asset state is
 * never run without the provider that reads it: its row is read strictly,
 * a Channel cannot be built over it without the provider, and a node
 * configured without one refuses to start over such a row and leaves the
 * row as it found it.
 */

import { expect } from 'chai';
import { Channel } from '../../src/lightning/channel/channel';
import type { IChannelState } from '../../src/lightning/channel/channel-state';
import type {
	IAuxiliaryCommitmentData,
	IChannelAuxiliaryProvider,
	IChannelAuxiliaryState
} from '../../src/lightning/channel/auxiliary';
import {
	copyAuxiliaryCommitment,
	requireAuxiliaryProvider
} from '../../src/lightning/channel/auxiliary';
import {
	HtlcDirection,
	isAnchorChannel,
	isOverlayChannel,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState,
	serializedChannelCarriesAssetState,
	channelRowFromStore,
	channelRowToStore
} from '../../src/lightning/storage/serialization';
import type { ISerializedChannelState } from '../../src/lightning/storage/serialization';
import {
	encodeFrame,
	decodeFrame,
	frameVersionForContent
} from '../../src/lightning/recovery/frame-codec';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	AuxiliaryChannelRowError,
	AuxiliaryProviderRequiredError
} from '../../src/lightning/node/types';
import {
	FIXTURE_PEER,
	channelStateFrame,
	ordinaryChannelState,
	storageDigests
} from './helpers/auxiliary-state-fixture';
import {
	connectNodes,
	createNode,
	makeNodeConfig,
	openReadyChannel
} from './helpers/loopback-nodes';

const key = (n: number): Buffer => getPublicKey(Buffer.alloc(32, n));

function channelType(...features: number[]): Buffer {
	const flags = FeatureFlags.empty();
	for (const feature of features) flags.setCompulsory(feature);
	return flags.toBuffer();
}

const amountRecord = (amount: bigint): Map<bigint, Buffer> => {
	const value = Buffer.alloc(8);
	value.writeBigUInt64BE(amount);
	return new Map([[65536n, value]]);
};

/** Storage and restore never call the provider: every method here throws. */
function provider(): IChannelAuxiliaryProvider {
	const unused = (): never => {
		throw new Error('storage and restore must not call the provider');
	};
	return {
		buildCommitment: unused,
		signHtlcs: unused,
		verifyHtlcs: unused,
		validateHtlc: unused,
		getHtlcAmount: unused,
		prepareShutdown: unused,
		verifyShutdown: unused,
		buildClose: unused
	};
}

function fullCommitment(): IAuxiliaryCommitmentData {
	return {
		secondLevelRevocationKey: key(0x61),
		secondLevelRevocationBasepoint: key(0x62),
		secondLevelCommitmentTxid: 'ef'.repeat(32),
		customData: Buffer.from('view:5'),
		outputLeaves: new Map([
			[0, { script: Buffer.from('6a20' + '01'.repeat(32), 'hex') }],
			[
				2,
				{
					script: Buffer.from('6a20' + '02'.repeat(32), 'hex'),
					leafVersion: 0xc0
				}
			]
		]),
		secondLevelLeaves: new Map([
			['OFFERED:0', { script: Buffer.from('6a20' + '03'.repeat(32), 'hex') }]
		]),
		htlcOutputIndexes: new Map([['OFFERED:0', 2]]),
		peerSignatures: new Map([[65538n, Buffer.alloc(64, 0x63)]])
	};
}

function bareCommitment(tag: string): IAuxiliaryCommitmentData {
	return {
		customData: Buffer.from(tag),
		outputLeaves: new Map(),
		secondLevelLeaves: new Map()
	};
}

/** Asset state with every optional field set. */
function fullAuxiliaryState(): IChannelAuxiliaryState {
	return {
		openingCsvPolicy: {
			mode: 'symmetric',
			minimumDelay: 144,
			maximumDelay: 2016,
			localDelay: 144
		},
		childRevocationBasepoints: new Map([['ab'.repeat(32), key(0x64)]]),
		channelData: Buffer.from('asset funding blob'),
		resolvedHtlcs: new Map([
			[
				'OFFERED:7',
				{
					htlcId: 7n,
					direction: HtlcDirection.OFFERED,
					paymentHash: Buffer.alloc(32, 0x65),
					auxiliaryAmount: 75n,
					customRecords: amountRecord(75n),
					outcome: 'fulfilled' as const
				}
			]
		]),
		localBalance: 825n,
		remoteBalance: 175n,
		localShutdownRecords: new Map([[65539n, key(0x66)]]),
		remoteShutdownRecords: new Map([[65539n, key(0x67)]]),
		closeTransactions: new Map([
			['cd'.repeat(32), Buffer.from('signed close assets')]
		]),
		acceptedClosingSigned: Buffer.alloc(40, 0x68),
		localCommitments: new Map([[5n, fullCommitment()]]),
		remoteCommitments: new Map([
			[5n, bareCommitment('view:5')],
			[6n, bareCommitment('view:6')]
		])
	};
}

/** A taproot overlay channel with asset state and asset HTLCs. */
function assetChannelState(
	auxiliaryState: IChannelAuxiliaryState = fullAuxiliaryState()
): IChannelState {
	const state = ordinaryChannelState('taproot');
	state.channelType = channelType(Feature.OPTION_TAPROOT_OVERLAY);
	state.fundingTaprootMerkleRoot = Buffer.alloc(32, 0xa7);
	state.auxiliaryState = auxiliaryState;
	state.lastSentAuxiliaryRecords = new Map([[65538n, Buffer.alloc(64, 0x69)]]);
	const offered = state.htlcs.get('offered-0')!;
	offered.customRecords = amountRecord(40n);
	offered.auxiliaryAmount = 40n;
	const received = state.htlcs.get('received-3')!;
	received.customRecords = amountRecord(20n);
	received.auxiliaryAmount = 20n;
	return state;
}

/** The row as storage holds it: through JSON and back. */
function stored(state: IChannelState): ISerializedChannelState {
	return JSON.parse(JSON.stringify(serializeChannelState(state)));
}

describe('asset channel state in the channel row', () => {
	describe('a channel without asset state', () => {
		// Taken with the code as it stood before asset channels touched the
		// storage codec, from the same fixture.
		const BEFORE = {
			taproot: {
				rowLength: 10078,
				rowSha256:
					'b0a5f6349d1dac3b66784f1dae636340e35ca2f74f738b615114880b11440be6',
				frame3Hash:
					'5b535701a23a1911dc734c49059792b7c560723fe7439e1f250309a1805ba4b5',
				frame4Hash:
					'2f97281c2d181e24191ba5bc7c8e261387a4f5a38a5c001072b763742a41d8e5'
			},
			anchors: {
				rowLength: 9908,
				rowSha256:
					'265f8e046089810d2126eb9d331fb0421a5414f9d7f6d51fb30ea3b6c65f5757',
				frame3Hash:
					'f956a3d132df664bdba58bae87e040e5537e5ec1baa51306cbf600b4b7c93c00',
				frame4Hash:
					'6c85a073f2e2e3ff3421e151bb279bc25c76e6d42c2bfcaaa9943a27d7742714'
			}
		};
		const HTLC_KEYS = [
			'key',
			'id',
			'amountMsat',
			'paymentHash',
			'cltvExpiry',
			'onionRoutingPacket',
			'direction',
			'state',
			'addRemoteCommitted'
		];

		for (const kind of ['taproot', 'anchors'] as const) {
			it(`stores a ${kind} channel row as the same bytes as before`, () => {
				const digests = storageDigests(ordinaryChannelState(kind));
				expect(digests.rowLength).to.equal(BEFORE[kind].rowLength);
				expect(digests.rowSha256).to.equal(BEFORE[kind].rowSha256);
				// The row still ends where it did: no asset key was added.
				expect(digests.keys.length).to.equal(128);
				expect(digests.keys[digests.keys.length - 1]).to.equal(
					'fforUsedEpochIds'
				);
				expect(digests.htlcKeys).to.deep.equal(HTLC_KEYS);
			});

			it(`hashes a recovery frame of a ${kind} channel as before`, () => {
				const digests = storageDigests(ordinaryChannelState(kind));
				expect(digests.frame3Hash).to.equal(BEFORE[kind].frame3Hash);
				expect(digests.frame4Hash).to.equal(BEFORE[kind].frame4Hash);
			});
		}

		it('reads back with no asset field, not even an undefined one', () => {
			const before = ordinaryChannelState('taproot');
			const row = stored(before);
			const after = deserializeChannelState(row);
			for (const field of [
				'fundingTaprootMerkleRoot',
				'auxiliaryState',
				'auxiliaryProvider',
				'lastSentAuxiliaryRecords'
			]) {
				expect(after).to.not.have.property(field);
			}
			for (const entry of after.htlcs.values()) {
				expect(entry).to.not.have.property('customRecords');
				expect(entry).to.not.have.property('auxiliaryAmount');
			}
			expect(JSON.stringify(serializeChannelState(after))).to.equal(
				JSON.stringify(row)
			);
		});

		it('is built into a Channel without the provider it is offered', () => {
			const withProvider = ordinaryChannelState('taproot');
			new Channel(withProvider, undefined, provider());
			expect(withProvider).to.not.have.property('auxiliaryProvider');
			const without = ordinaryChannelState('anchors');
			expect(() => new Channel(without)).to.not.throw();
		});
	});

	describe('the overlay channel type', () => {
		it('is the overlay bit with neither static_remotekey nor option_taproot', () => {
			const overlay = Feature.OPTION_TAPROOT_OVERLAY;
			expect(isOverlayChannel(channelType(overlay))).to.equal(true);
			expect(
				isOverlayChannel(
					channelType(overlay, Feature.SCID_ALIAS, Feature.ZERO_CONF)
				)
			).to.equal(true);
			expect(
				isOverlayChannel(
					channelType(
						overlay,
						Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS,
						Feature.OPTION_ASSET_CHILD_CUSTODY
					)
				)
			).to.equal(true);
			expect(isOverlayChannel(null)).to.equal(false);
			expect(isOverlayChannel(Buffer.alloc(0))).to.equal(false);
		});

		it('leaves every type a node could already hold as the kind it was', () => {
			// A peer could always add an unknown bit to a type that carried
			// static_remotekey or option_taproot, and the open was accepted.
			const legacy = channelType(
				Feature.STATIC_REMOTE_KEY,
				Feature.OPTION_TAPROOT_OVERLAY
			);
			expect(isOverlayChannel(legacy)).to.equal(false);
			expect(isTaprootChannel(legacy)).to.equal(false);
			expect(isAnchorChannel(legacy)).to.equal(false);
			const taproot = channelType(
				Feature.OPTION_TAPROOT,
				Feature.OPTION_TAPROOT_OVERLAY
			);
			expect(isOverlayChannel(taproot)).to.equal(false);
			expect(isTaprootChannel(taproot)).to.equal(true);

			// Such a channel restores without a provider, as it did.
			const state = ordinaryChannelState('anchors');
			state.channelType = legacy;
			expect(() => new Channel(state)).to.not.throw();
			const row = stored(state);
			expect(Object.keys(row)).to.not.include('auxiliaryState');
		});
	});

	describe('a channel with asset state', () => {
		it('round trips every asset field through its row', () => {
			const before = assetChannelState();
			const row = stored(before);
			const after = deserializeChannelState(row);

			expect(after.fundingTaprootMerkleRoot).to.deep.equal(
				before.fundingTaprootMerkleRoot
			);
			expect(after.auxiliaryState).to.deep.equal(before.auxiliaryState);
			expect(after.lastSentAuxiliaryRecords).to.deep.equal(
				before.lastSentAuxiliaryRecords
			);
			expect(after.htlcs.get('offered-0')!.customRecords).to.deep.equal(
				amountRecord(40n)
			);
			expect(after.htlcs.get('offered-0')!.auxiliaryAmount).to.equal(40n);
			expect(after.htlcs.get('received-3')!.auxiliaryAmount).to.equal(20n);
			// A second write of what was read is the same row.
			expect(JSON.stringify(serializeChannelState(after))).to.equal(
				JSON.stringify(row)
			);
		});

		it('writes its asset keys after every key an ordinary row has', () => {
			const ordinary = Object.keys(
				serializeChannelState(ordinaryChannelState('taproot'))
			);
			const asset = Object.keys(serializeChannelState(assetChannelState()));
			expect(asset.slice(0, ordinary.length)).to.deep.equal(ordinary);
			expect(asset.slice(ordinary.length)).to.deep.equal([
				'fundingTaprootMerkleRoot',
				'auxiliaryState',
				'lastSentAuxiliaryRecords'
			]);
			const htlc = Object.keys(
				serializeChannelState(assetChannelState()).htlcs[0]
			);
			expect(htlc.slice(-2)).to.deep.equal([
				'customRecords',
				'auxiliaryAmount'
			]);
		});

		it('writes an optional asset field only when the channel has it', () => {
			const bare: IChannelAuxiliaryState = {
				channelData: Buffer.from('asset funding blob'),
				localBalance: 1000n,
				remoteBalance: 0n,
				localCommitments: new Map([[0n, bareCommitment('view:0')]]),
				remoteCommitments: new Map([[0n, bareCommitment('view:0')]])
			};
			const state = assetChannelState(bare);
			delete state.lastSentAuxiliaryRecords;
			const row = stored(state);
			expect(Object.keys(row.auxiliaryState!)).to.deep.equal([
				'channelData',
				'localBalance',
				'remoteBalance',
				'localCommitments',
				'remoteCommitments'
			]);
			expect(Object.keys(row.auxiliaryState!.localCommitments[0][1]))
				.to.deep //
				.equal(['customData', 'outputLeaves', 'secondLevelLeaves']);
			expect(Object.keys(row)).to.not.include('lastSentAuxiliaryRecords');
			const after = deserializeChannelState(row);
			expect(after.auxiliaryState).to.deep.equal(bare);
			expect(Object.keys(after.auxiliaryState!)).to.deep.equal(
				Object.keys(bare)
			);
		});

		it('never writes the provider', () => {
			const state = assetChannelState();
			state.auxiliaryProvider = provider();
			const json = JSON.stringify(serializeChannelState(state));
			expect(json).to.not.include('auxiliaryProvider');
			expect(deserializeChannelState(JSON.parse(json))).to.not.have.property(
				'auxiliaryProvider'
			);
		});

		it('is carried whole by a recovery frame, which is marked version 5', () => {
			const before = assetChannelState();
			const written = channelStateFrame(before, 3);
			// The journal stamps every frame with this answer.
			expect(frameVersionForContent(written)).to.equal(5);
			written.version = 5;
			const frame = decodeFrame(encodeFrame(written));
			expect(frame.version).to.equal(5);
			const mutation = frame.mutations[0];
			if (mutation.type !== 'channel_state') {
				throw new Error('expected a channel_state mutation');
			}
			expect(mutation.state.auxiliaryState).to.deep.equal(
				before.auxiliaryState
			);
			expect(mutation.state.fundingTaprootMerkleRoot).to.deep.equal(
				before.fundingTaprootMerkleRoot
			);
			expect(
				mutation.state.htlcs.get('received-3')!.customRecords
			).to.deep.equal(amountRecord(20n));

			// Under any older version the same content is refused: a release
			// that reads those versions would drop the asset state.
			for (const version of [1, 2, 3, 4] as const) {
				expect(() =>
					decodeFrame(encodeFrame(channelStateFrame(before, version)))
				).to.throw('Asset channel state requires recovery frame version 5');
			}
		});

		it('leaves the frame of an ordinary channel at the version it always had', () => {
			for (const kind of ['taproot', 'anchors'] as const) {
				const frame = channelStateFrame(ordinaryChannelState(kind), 3);
				expect(frameVersionForContent(frame)).to.be.oneOf([3, 4]);
			}
			// And version 5 without asset state still reads: the version
			// says what a frame may carry, not what it must.
			const plain = channelStateFrame(ordinaryChannelState('taproot'), 5);
			expect(decodeFrame(encodeFrame(plain)).version).to.equal(5);
		});

		const corruptions: Array<
			[string, (row: ISerializedChannelState) => void, string]
		> = [
			[
				'a balance with a leading zero',
				(row): void => {
					row.auxiliaryState!.localBalance = '0825';
				},
				'Malformed serialized asset integer'
			],
			[
				'a balance above a u64',
				(row): void => {
					row.auxiliaryState!.remoteBalance = '18446744073709551616';
				},
				'Serialized asset integer is out of range'
			],
			[
				'balances that sum past a u64',
				(row): void => {
					row.auxiliaryState!.localBalance = '18446744073709551615';
				},
				'Serialized asset balances overflow'
			],
			[
				'a commitment number stored twice',
				(row): void => {
					const commitments = row.auxiliaryState!.remoteCommitments;
					commitments.push(commitments[0]);
				},
				'Duplicate serialized asset map entry'
			],
			[
				'a commitment number above 48 bits',
				(row): void => {
					row.auxiliaryState!.remoteCommitments[0][0] = '281474976710656';
				},
				'Serialized asset integer is out of range'
			],
			[
				'a leaf version with the parity bit set',
				(row): void => {
					row.auxiliaryState!.localCommitments[0][1].outputLeaves[0][1].leafVersion = 0xc1;
				},
				'Malformed serialized auxiliary leaf'
			],
			[
				'a second-level leaf under a malformed HTLC identity',
				(row): void => {
					row.auxiliaryState!.localCommitments[0][1].secondLevelLeaves[0][0] =
						'offered:0';
				},
				'Malformed serialized asset HTLC identity'
			],
			[
				'a second-level revocation key that is not a point',
				(row): void => {
					row.auxiliaryState!.localCommitments[0][1].secondLevelRevocationKey =
						'02' + '00'.repeat(32);
				},
				'Malformed child custody point'
			],
			[
				'a peer signature record stored twice',
				(row): void => {
					const records =
						row.auxiliaryState!.localCommitments[0][1].peerSignatures!;
					records.push(records[0]);
				},
				'Duplicate serialized custom record'
			],
			[
				'a custom record below the custom range',
				(row): void => {
					row.lastSentAuxiliaryRecords![0][0] = '65535';
				},
				'Invalid or reserved Lightning custom record'
			],
			[
				'a funding root that is not 32 bytes',
				(row): void => {
					row.fundingTaprootMerkleRoot = 'a7'.repeat(31);
				},
				'Malformed serialized asset funding root'
			],
			[
				'a resolution filed under another HTLC',
				(row): void => {
					row.auxiliaryState!.resolvedHtlcs![0][0] = 'RECEIVED:7';
				},
				'Malformed serialized asset resolution'
			],
			[
				'a CSV policy whose maximum is below its minimum',
				(row): void => {
					row.auxiliaryState!.openingCsvPolicy!.maximumDelay = 100;
				},
				'Invalid persisted asset channel CSV policy'
			],
			[
				'asset data that is not hex',
				(row): void => {
					row.auxiliaryState!.channelData = 'zz';
				},
				'Malformed serialized asset bytes'
			],
			[
				'an HTLC asset amount that is not a canonical integer',
				(row): void => {
					row.htlcs[0].auxiliaryAmount = '-1';
				},
				'Malformed serialized asset amount'
			],
			[
				'an HTLC asset amount above a u64',
				(row): void => {
					row.htlcs[0].auxiliaryAmount = '18446744073709551616';
				},
				'Serialized asset amount is out of range'
			],
			[
				'asset state that is not an object',
				(row): void => {
					(row as { auxiliaryState: unknown }).auxiliaryState = null;
				},
				'Malformed serialized asset channel state'
			]
		];
		for (const [name, corrupt, message] of corruptions) {
			it(`refuses a row with ${name}`, () => {
				const row = stored(assetChannelState());
				expect(() => deserializeChannelState(row)).to.not.throw();
				corrupt(row);
				expect(() => deserializeChannelState(row)).to.throw(message);
			});
		}

		it('copies a commitment so that neither copy can change the other', () => {
			const original = fullCommitment();
			const copy = copyAuxiliaryCommitment(original);
			expect(copy).to.deep.equal(original);
			copy.customData[0] ^= 0xff;
			copy.outputLeaves.get(0)!.script[0] ^= 0xff;
			copy.secondLevelLeaves.delete('OFFERED:0');
			copy.peerSignatures!.get(65538n)![0] ^= 0xff;
			copy.htlcOutputIndexes!.set('OFFERED:0', 9);
			copy.secondLevelRevocationKey![1] ^= 0xff;
			expect(original).to.deep.equal(fullCommitment());
			// An absent optional field stays absent in the copy.
			expect(
				Object.keys(copyAuxiliaryCommitment(bareCommitment('view')))
			).to.deep.equal(['customData', 'outputLeaves', 'secondLevelLeaves']);
		});
	});

	describe('a Channel over asset state', () => {
		const restoredState = (): IChannelState =>
			deserializeChannelState(stored(assetChannelState()));

		it('cannot be built without the provider', () => {
			const state = restoredState();
			expect(state.auxiliaryProvider).to.equal(undefined);
			expect(() => new Channel(state)).to.throw('provider');
		});

		it('has the provider attached again on restore', () => {
			const state = restoredState();
			const reattached = provider();
			const channel = new Channel(state, undefined, reattached);
			expect(channel.getFullState().auxiliaryProvider).to.equal(reattached);
			expect(requireAuxiliaryProvider(channel.getFullState())).to.equal(
				reattached
			);
			// Still not written with the row.
			expect(
				JSON.stringify(serializeChannelState(channel.getFullState()))
			).to.equal(JSON.stringify(stored(assetChannelState())));
		});

		it('cannot be built when only part of the asset state is there', () => {
			const noRoot = restoredState();
			delete noRoot.fundingTaprootMerkleRoot;
			expect(() => new Channel(noRoot, undefined, provider())).to.throw(
				'Asset channel state or auxiliary provider is unavailable'
			);

			const shortRoot = restoredState();
			shortRoot.fundingTaprootMerkleRoot = Buffer.alloc(31, 0xa7);
			expect(() => new Channel(shortRoot, undefined, provider())).to.throw(
				'Asset channel state or auxiliary provider is unavailable'
			);

			// The overlay type alone is enough to demand the rest.
			const typeOnly = restoredState();
			delete typeOnly.auxiliaryState;
			delete typeOnly.fundingTaprootMerkleRoot;
			expect(() => new Channel(typeOnly, undefined, provider())).to.throw(
				'Asset channel state or auxiliary provider is unavailable'
			);

			// So is the funding root alone, whatever the type says.
			const rootOnly = ordinaryChannelState('taproot');
			rootOnly.fundingTaprootMerkleRoot = Buffer.alloc(32, 0xa7);
			expect(() => new Channel(rootOnly)).to.throw('provider');
			// The refusal names the channel.
			expect(() => new Channel(rootOnly)).to.throw(
				rootOnly.channelId!.toString('hex')
			);
		});
	});

	describe('a node over stored asset channels', function () {
		this.timeout(20000);
		const nodes: LightningNode[] = [];
		afterEach(() => {
			for (const node of nodes.splice(0)) node.destroy();
		});

		type Row = Record<string, unknown>;
		/** Change a stored row in place, past the writer, as damage would. */
		function tamperRow(
			storage: MemoryStorage,
			id: string,
			change: (row: Row) => void
		): void {
			const table = (
				storage as unknown as {
					channels: {
						get(id: string): { json: string; peerPubkey: string } | undefined;
						put(id: string, row: { json: string; peerPubkey: string }): void;
					};
				}
			).channels;
			const row = table.get(id)!;
			// An asset channel's row is stored inside its envelope.
			const parsed = JSON.parse(row.json) as { channel: Row };
			change(parsed.channel);
			table.put(id, { ...row, json: JSON.stringify(parsed) });
		}

		/**
		 * A node's storage with one channel that was made an asset channel,
		 * and then, optionally, damaged in storage.
		 */
		function storageWithAssetChannel(
			seed: number,
			damage?: (row: Row) => void
		): { storage: MemoryStorage; id: string } {
			const storage = new MemoryStorage();
			const alice = createNode('aux-state', seed, undefined, { storage });
			const bob = createNode('aux-state', seed + 1);
			nodes.push(alice, bob);
			alice.on('node:error', () => {});
			bob.on('node:error', () => {});
			connectNodes(alice, bob);
			const id = openReadyChannel(alice, bob).toString('hex');
			alice.destroy();
			nodes.splice(nodes.indexOf(alice), 1);

			const row = storage.loadChannel(id)!;
			row.state.fundingTaprootMerkleRoot = Buffer.alloc(32, 0xa7);
			row.state.auxiliaryState = fullAuxiliaryState();
			storage.saveChannel(id, row.state, row.peerPubkey);
			if (damage) tamperRow(storage, id, damage);
			return { storage, id };
		}

		/** Every stored row as it reads, for a before and after comparison. */
		const rows = (storage: MemoryStorage): unknown => storage.loadAllChannels();

		const overlayHex = channelType(Feature.OPTION_TAPROOT_OVERLAY).toString(
			'hex'
		);
		const kinds: Array<[string, ((row: Row) => void) | undefined]> = [
			['asset state', undefined],
			[
				'an asset funding root alone',
				(row): void => {
					delete row.auxiliaryState;
				}
			],
			[
				'the overlay channel type alone',
				(row): void => {
					delete row.auxiliaryState;
					delete row.fundingTaprootMerkleRoot;
					row.channelType = overlayHex;
				}
			]
		];
		kinds.forEach(([name, damage], index) => {
			it(`refuses to start without a provider over a row with ${name}, and changes no row`, () => {
				const { storage, id } = storageWithAssetChannel(10 + index * 2, damage);
				const before = rows(storage);

				let thrown: unknown;
				try {
					nodes.push(
						new LightningNode({
							...makeNodeConfig('aux-state', 10 + index * 2),
							storage
						})
					);
				} catch (error) {
					thrown = error;
				}
				expect(thrown).to.be.instanceOf(AuxiliaryProviderRequiredError);
				const refusal = thrown as AuxiliaryProviderRequiredError;
				expect(refusal.code).to.equal('AUXILIARY_PROVIDER_REQUIRED');
				expect(refusal.channelIds).to.deep.equal([id]);
				expect(refusal.message).to.include(id);
				expect(rows(storage)).to.deep.equal(before);
			});
		});

		kinds.slice(1).forEach(([name, damage], index) => {
			it(`refuses to start with a provider over a row with ${name}, by name, and changes no row`, () => {
				const { storage, id } = storageWithAssetChannel(30 + index * 2, damage);
				const before = rows(storage);

				let thrown: unknown;
				try {
					nodes.push(
						new LightningNode({
							...makeNodeConfig('aux-state', 30 + index * 2),
							storage,
							auxiliaryChannels: {
								provider: provider(),
								resolveIncoming: (): undefined => undefined
							}
						})
					);
				} catch (error) {
					thrown = error;
				}
				expect(thrown).to.be.instanceOf(AuxiliaryChannelRowError);
				const refusal = thrown as AuxiliaryChannelRowError;
				expect(refusal.code).to.equal('AUXILIARY_CHANNEL_ROW_INVALID');
				expect(refusal.channelIds).to.deep.equal([id]);
				expect(refusal.reasons.get(id)).to.include('without its asset state');
				expect(refusal.message).to.include(id);
				expect(rows(storage)).to.deep.equal(before);
			});
		});

		it('starts with the provider and hands it to the restored channel', () => {
			const { storage, id } = storageWithAssetChannel(20);
			const before = rows(storage);
			const configured = provider();
			const alice = new LightningNode({
				...makeNodeConfig('aux-state', 20),
				storage,
				auxiliaryChannels: {
					provider: configured,
					resolveIncoming: (): undefined => undefined
				}
			});
			nodes.push(alice);
			alice.on('node:error', () => {});

			const channel = alice
				.getChannelManager()
				.getChannel(Buffer.from(id, 'hex'))!;
			expect(channel.getFullState().auxiliaryProvider).to.equal(configured);
			expect(channel.getFullState().auxiliaryState).to.deep.equal(
				fullAuxiliaryState()
			);
			// Restoring it wrote nothing the row did not already say.
			expect(rows(storage)).to.deep.equal(before);
		});
	});

	describe('the writer and the reader of asset state agree', () => {
		type Row = ISerializedChannelState;
		// Each fault is made twice: in a state about to be saved, and in a
		// row about to be read. The save must fail, and with the reader's
		// own complaint, so nothing is ever stored that cannot be read back.
		const faults: Array<
			[string, (state: IChannelState) => void, (row: Row) => void]
		> = [
			[
				'a resolution for no assets',
				(state): void => {
					state.auxiliaryState!.resolvedHtlcs!.get(
						'OFFERED:7'
					)!.auxiliaryAmount = 0n;
				},
				(row): void => {
					row.auxiliaryState!.resolvedHtlcs![0][1].auxiliaryAmount = '0';
				}
			],
			[
				'a funding root that is not 32 bytes',
				(state): void => {
					state.fundingTaprootMerkleRoot = Buffer.alloc(31, 0xa7);
				},
				(row): void => {
					row.fundingTaprootMerkleRoot = 'a7'.repeat(31);
				}
			],
			[
				'a child commitment txid in upper case',
				(state): void => {
					state.auxiliaryState!.localCommitments.get(
						5n
					)!.secondLevelCommitmentTxid = 'EF'.repeat(32);
				},
				(row): void => {
					row.auxiliaryState!.localCommitments[0][1].secondLevelCommitmentTxid =
						'EF'.repeat(32);
				}
			],
			[
				'peer signatures under a type below 65536',
				(state): void => {
					state.auxiliaryState!.localCommitments.get(5n)!.peerSignatures =
						new Map([[5n, Buffer.alloc(4)]]);
				},
				(row): void => {
					row.auxiliaryState!.localCommitments[0][1].peerSignatures = [
						['5', '00000000']
					];
				}
			],
			[
				'an HTLC asset amount above a u64',
				(state): void => {
					state.htlcs.get('offered-0')!.auxiliaryAmount = 1n << 64n;
				},
				(row): void => {
					row.htlcs.find((h) => h.auxiliaryAmount === '40')!.auxiliaryAmount = (
						1n << 64n
					).toString();
				}
			],
			[
				'a leaf script over 10000 bytes',
				(state): void => {
					state
						.auxiliaryState!.localCommitments.get(5n)!
						.outputLeaves.set(0, { script: Buffer.alloc(10001) });
				},
				(row): void => {
					row.auxiliaryState!.localCommitments[0][1].outputLeaves[0][1].script =
						'00'.repeat(10001);
				}
			]
		];
		for (const [name, inState, inRow] of faults) {
			it(`refuses to write ${name}, as it refuses to read it`, () => {
				const row = stored(assetChannelState());
				inRow(row);
				let complaint: string | undefined;
				try {
					deserializeChannelState(row);
				} catch (error) {
					complaint = (error as Error).message;
				}
				expect(complaint, 'the reader refuses the row').to.be.a('string');

				const state = assetChannelState();
				inState(state);
				expect(() => serializeChannelState(state)).to.throw(complaint!);
				// A recovery frame is written by the same serializer.
				expect(() => encodeFrame(channelStateFrame(state, 5))).to.throw(
					complaint!
				);
			});
		}

		it('refuses to write an asset channel that is not whole', () => {
			const id = assetChannelState().channelId!.toString('hex');
			const typeOnly = assetChannelState();
			delete typeOnly.auxiliaryState;
			delete typeOnly.fundingTaprootMerkleRoot;
			const rootOnly = ordinaryChannelState('taproot');
			rootOnly.fundingTaprootMerkleRoot = Buffer.alloc(32, 0xa7);
			const noRoot = assetChannelState();
			delete noRoot.fundingTaprootMerkleRoot;
			for (const state of [typeOnly, rootOnly, noRoot]) {
				expect(() => serializeChannelState(state)).to.throw(
					`Refusing to store an incomplete asset channel (${id})`
				);
			}
			// Asset state and its root are whole whatever the type says: the
			// type is settled by the opening, after the asset state exists.
			const beforeTheType = assetChannelState();
			beforeTheType.channelType = ordinaryChannelState('taproot').channelType;
			expect(() => serializeChannelState(beforeTheType)).to.not.throw();
		});

		it('reads back, equal, every asset state the writer accepts', () => {
			// A small deterministic generator: the same states on every run.
			const generator = (seed: number): (() => number) => {
				let a = seed >>> 0;
				return (): number => {
					a = (a + 0x6d2b79f5) >>> 0;
					let t = a;
					t = Math.imul(t ^ (t >>> 15), t | 1);
					t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
					return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
				};
			};
			const build = (next: () => number): IChannelState => {
				const int = (n: number): number => Math.floor(next() * n);
				const maybe = (): boolean => next() < 0.5;
				const bytesOf = (length: number): Buffer =>
					Buffer.from(Array.from({ length }, () => int(256)));
				const blob = (max: number): Buffer => bytesOf(int(max + 1));
				const txid = (): string => bytesOf(32).toString('hex');
				const point = (): Buffer => key(1 + int(200));
				const records = (): Map<bigint, Buffer> =>
					new Map(
						Array.from({ length: 1 + int(3) }, (): [bigint, Buffer] => [
							65536n + BigInt(int(5000)),
							blob(70)
						])
					);
				const htlcId = (): string =>
					`${maybe() ? 'OFFERED' : 'RECEIVED'}:${int(1000)}`;
				const leaf = (): { script: Buffer; leafVersion?: number } => ({
					script: blob(60),
					...(maybe() ? { leafVersion: [0xc0, 0xc2, 0x02][int(3)] } : {})
				});
				const commitment = (): IAuxiliaryCommitmentData => ({
					customData: blob(50),
					...(maybe() ? { secondLevelRevocationKey: point() } : {}),
					...(maybe() ? { secondLevelRevocationBasepoint: point() } : {}),
					...(maybe() ? { secondLevelCommitmentTxid: txid() } : {}),
					...(maybe()
						? {
								htlcOutputIndexes: new Map(
									Array.from({ length: int(4) }, (): [string, number] => [
										htlcId(),
										int(500)
									])
								)
						  }
						: {}),
					outputLeaves: new Map(
						Array.from(
							{ length: int(4) },
							(): [number, ReturnType<typeof leaf>] => [int(500), leaf()]
						)
					),
					secondLevelLeaves: new Map(
						Array.from(
							{ length: int(3) },
							(): [string, ReturnType<typeof leaf>] => [htlcId(), leaf()]
						)
					),
					...(maybe() ? { peerSignatures: records() } : {})
				});
				const commitments = (): Map<bigint, IAuxiliaryCommitmentData> =>
					new Map(
						Array.from(
							{ length: int(4) },
							(): [bigint, IAuxiliaryCommitmentData] => [
								BigInt(int(1_000_000)),
								commitment()
							]
						)
					);
				const auxiliaryState: IChannelAuxiliaryState = {
					...(maybe()
						? {
								openingCsvPolicy: {
									mode: 'symmetric',
									minimumDelay: 144,
									maximumDelay: 2016,
									localDelay: 144 + int(1000)
								}
						  }
						: {}),
					...(maybe()
						? {
								childRevocationBasepoints: new Map(
									Array.from({ length: int(3) }, (): [string, Buffer] => [
										txid(),
										point()
									])
								)
						  }
						: {}),
					channelData: blob(80),
					...(maybe()
						? {
								resolvedHtlcs: new Map(
									Array.from({ length: int(4) }, () => {
										const direction = maybe()
											? HtlcDirection.OFFERED
											: HtlcDirection.RECEIVED;
										const id = BigInt(int(1000));
										return [
											`${direction}:${id}`,
											{
												htlcId: id,
												direction,
												paymentHash: bytesOf(32),
												auxiliaryAmount: 1n + BigInt(int(1_000_000)),
												...(maybe() ? { customRecords: records() } : {}),
												outcome: maybe()
													? ('fulfilled' as const)
													: ('failed' as const)
											}
										] as const;
									})
								)
						  }
						: {}),
					localBalance: maybe() ? BigInt(int(2 ** 31)) : (1n << 63n) - 1n,
					remoteBalance: maybe() ? BigInt(int(2 ** 31)) : 1n << 63n,
					...(maybe() ? { localShutdownRecords: records() } : {}),
					...(maybe() ? { remoteShutdownRecords: records() } : {}),
					...(maybe()
						? {
								closeTransactions: new Map(
									Array.from({ length: int(3) }, (): [string, Buffer] => [
										txid(),
										blob(40)
									])
								)
						  }
						: {}),
					...(maybe() ? { acceptedClosingSigned: blob(60) } : {}),
					localCommitments: commitments(),
					remoteCommitments: commitments()
				};
				const state = assetChannelState(auxiliaryState);
				state.fundingTaprootMerkleRoot = bytesOf(32);
				if (maybe()) delete state.lastSentAuxiliaryRecords;
				else state.lastSentAuxiliaryRecords = records();
				const offered = state.htlcs.get('offered-0')!;
				offered.customRecords = records();
				offered.auxiliaryAmount = maybe()
					? BigInt(int(2 ** 31))
					: (1n << 64n) - 1n;
				return state;
			};
			const assetParts = (state: IChannelState): unknown => ({
				root: state.fundingTaprootMerkleRoot,
				auxiliaryState: state.auxiliaryState,
				lastSent: state.lastSentAuxiliaryRecords,
				htlcs: [...state.htlcs].map(([id, htlc]) => [
					id,
					htlc.customRecords,
					htlc.auxiliaryAmount
				])
			});

			for (let seed = 1; seed <= 150; seed++) {
				const state = build(generator(seed));
				const row = stored(state);
				const fromRow = deserializeChannelState(row);
				expect(assetParts(fromRow), `row ${seed}`).to.deep.equal(
					assetParts(state)
				);
				expect(JSON.stringify(serializeChannelState(fromRow))).to.equal(
					JSON.stringify(row)
				);

				const frame = channelStateFrame(state, 5);
				expect(frameVersionForContent(frame)).to.equal(5);
				const mutation = decodeFrame(encodeFrame(frame)).mutations[0];
				if (mutation.type !== 'channel_state') {
					throw new Error('expected a channel_state mutation');
				}
				expect(assetParts(mutation.state), `frame ${seed}`).to.deep.equal(
					assetParts(state)
				);
			}
		});
	});

	describe('an asset row that SQLite cannot decode', function () {
		this.timeout(20000);
		const nodes: LightningNode[] = [];
		const stores: SqliteStorage[] = [];
		afterEach(() => {
			for (const node of nodes.splice(0)) node.destroy();
			for (const store of stores.splice(0)) store.close();
		});

		type Sql = {
			prepare(sql: string): {
				run(...values: unknown[]): unknown;
				get(...values: unknown[]): unknown;
			};
		};
		const sql = (store: SqliteStorage): Sql =>
			(store as unknown as { db: Sql }).db;
		const rawRow = (store: SqliteStorage, id: string): string =>
			(
				sql(store)
					.prepare('SELECT state_json FROM channels WHERE channel_id = ?')
					.get(id) as { state_json: string }
			).state_json;
		const writeRaw = (store: SqliteStorage, id: string, json: string): void => {
			sql(store)
				.prepare('UPDATE channels SET state_json = ? WHERE channel_id = ?')
				.run(json, id);
		};
		/** One asset channel and one ordinary channel, both stored whole. */
		function storage(): { store: SqliteStorage; asset: string; plain: string } {
			const store = new SqliteStorage(':memory:');
			store.open();
			stores.push(store);
			const assetState = assetChannelState();
			const plainState = ordinaryChannelState('anchors');
			const asset = assetState.channelId!.toString('hex');
			const plain = plainState.channelId!.toString('hex');
			expect(asset).to.not.equal(plain);
			store.saveChannel(asset, assetState, FIXTURE_PEER);
			store.saveChannel(plain, plainState, FIXTURE_PEER);
			return { store, asset, plain };
		}
		/** Make a stored row undecodable while it still parses. */
		function damage(store: SqliteStorage, id: string): void {
			const row = JSON.parse(rawRow(store, id)) as Record<string, unknown>;
			const channel = (row.channel ?? row) as Record<string, unknown>;
			channel.htlcs = 5;
			writeRaw(store, id, JSON.stringify(row));
		}

		it('stores an asset channel inside an envelope, and any other channel as the row it always was', () => {
			const { store, asset, plain } = storage();
			const plainState = ordinaryChannelState('anchors');
			expect(rawRow(store, plain)).to.equal(
				JSON.stringify(
					serializeChannelState(plainState, { htlcHistory: 'none' })
				)
			);
			const envelope = JSON.parse(rawRow(store, asset)) as Record<
				string,
				unknown
			>;
			expect(Object.keys(envelope)).to.deep.equal([
				'assetChannelRow',
				'channel'
			]);
			expect(envelope.assetChannelRow).to.equal(1);
			expect(JSON.stringify(envelope.channel)).to.equal(
				JSON.stringify(
					serializeChannelState(assetChannelState(), { htlcHistory: 'none' })
				)
			);
			// Nothing a release from before asset channels reads a channel
			// from is at the top of the envelope, so it cannot decode the row
			// and skips it, where it would have loaded the bare row as an
			// ordinary channel and saved it back without its asset state.
			for (const field of Object.keys(
				stored(ordinaryChannelState('anchors'))
			)) {
				expect(envelope).to.not.have.property(field);
			}
			expect(() =>
				deserializeChannelState(
					envelope as unknown as Parameters<typeof deserializeChannelState>[0]
				)
			).to.throw();
			// It reads back whole.
			const loaded = store.loadChannel(asset)!;
			expect(loaded.state.auxiliaryState).to.deep.equal(
				assetChannelState().auxiliaryState
			);
			expect(
				store.loadAllChannels().map((row) => row.channelId)
			).to.have.members([asset, plain]);
		});

		it('reads exactly the stored forms the writer makes', () => {
			const asset = stored(assetChannelState());
			const plain = stored(ordinaryChannelState('anchors'));
			expect(channelRowToStore(plain)).to.equal(plain);
			expect(channelRowFromStore(plain)).to.equal(plain);
			const envelope = channelRowToStore(asset);
			expect(envelope).to.deep.equal({ assetChannelRow: 1, channel: asset });
			expect(channelRowFromStore(envelope)).to.equal(asset);
			expect(serializedChannelCarriesAssetState(envelope)).to.equal(true);

			expect(() => channelRowFromStore(asset)).to.throw(
				'An asset channel row is stored without its envelope'
			);
			for (const malformed of [
				{ assetChannelRow: 2, channel: asset },
				{ assetChannelRow: '1', channel: asset },
				{ assetChannelRow: 1, channel: asset, extra: true },
				{ assetChannelRow: 1 },
				{ assetChannelRow: 1, channel: plain },
				{ assetChannelRow: 1, channel: [asset] },
				{ assetChannelRow: 1, channel: { assetChannelRow: 1, channel: asset } }
			]) {
				expect(() => channelRowFromStore(malformed)).to.throw(
					'Malformed stored asset channel row'
				);
				expect(serializedChannelCarriesAssetState(malformed)).to.equal(true);
			}
		});

		it('tells an asset row from its keys alone', () => {
			const asset = stored(assetChannelState());
			expect(serializedChannelCarriesAssetState(asset)).to.equal(true);
			const { auxiliaryState: _state, ...rootOnly } = asset;
			expect(serializedChannelCarriesAssetState(rootOnly)).to.equal(true);
			const { fundingTaprootMerkleRoot: _root, ...typeOnly } = rootOnly;
			expect(serializedChannelCarriesAssetState(typeOnly)).to.equal(true);
			for (const row of [
				stored(ordinaryChannelState('taproot')),
				stored(ordinaryChannelState('anchors')),
				{ ...typeOnly, channelType: 'not hex' },
				{ ...typeOnly, channelType: null },
				null,
				'row',
				5
			]) {
				expect(serializedChannelCarriesAssetState(row)).to.equal(false);
			}
		});

		it('remembers the asset row it skipped, and not an ordinary one', () => {
			const { store, asset, plain } = storage();
			expect(store.loadAllChannels().length).to.equal(2);
			expect(store.unreadableAssetChannelIds()).to.deep.equal([]);

			const whole = rawRow(store, asset);
			damage(store, asset);
			damage(store, plain);
			expect(store.loadAllChannels()).to.deep.equal([]);
			expect(store.corruptRowCount()).to.equal(2);
			expect(store.unreadableAssetChannelIds()).to.deep.equal([asset]);

			// The answer follows the last load, not the first.
			writeRaw(store, asset, whole);
			expect(store.loadAllChannels().map((row) => row.channelId)).to.deep.equal(
				[asset]
			);
			expect(store.unreadableAssetChannelIds()).to.deep.equal([]);
		});

		it('still refuses to start without a provider, and changes no row', () => {
			const { store, asset } = storage();
			damage(store, asset);
			const before = rawRow(store, asset);
			let thrown: unknown;
			try {
				nodes.push(
					new LightningNode({
						...makeNodeConfig('aux-state', 40),
						storage: store
					})
				);
			} catch (error) {
				thrown = error;
			}
			expect(thrown).to.be.instanceOf(AuxiliaryProviderRequiredError);
			expect(
				(thrown as AuxiliaryProviderRequiredError).channelIds
			).to.deep.equal([asset]);
			expect(rawRow(store, asset)).to.equal(before);
		});

		it('refuses to start with a provider too, naming the channel, and changes no row', () => {
			const { store, asset } = storage();
			damage(store, asset);
			const before = rawRow(store, asset);
			let thrown: unknown;
			try {
				nodes.push(
					new LightningNode({
						...makeNodeConfig('aux-state', 42),
						storage: store,
						auxiliaryChannels: {
							provider: provider(),
							resolveIncoming: (): undefined => undefined
						}
					})
				);
			} catch (error) {
				thrown = error;
			}
			expect(thrown).to.be.instanceOf(AuxiliaryChannelRowError);
			const refusal = thrown as AuxiliaryChannelRowError;
			expect(refusal.code).to.equal('AUXILIARY_CHANNEL_ROW_INVALID');
			expect(refusal.channelIds).to.deep.equal([asset]);
			expect(refusal.reasons.get(asset)).to.equal(
				'the stored row cannot be read'
			);
			expect(rawRow(store, asset)).to.equal(before);
		});
	});
});
