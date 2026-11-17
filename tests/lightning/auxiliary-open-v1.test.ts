/**
 * Issue #2093, step 7: an asset channel opens over open_channel.
 *
 * An asset channel is a taproot overlay channel, and it is opened with the
 * v1 messages whatever kind of channel the node would otherwise open: the
 * choice is made by the channel, from its asset funding, and never by the
 * node's taproot preference or by what the peer negotiated for ordinary
 * channels. A node without a provider opens and answers as it always did,
 * which the transcripts below pin against bytes captured from the previous
 * release under the same fixed randomness.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import sinon from 'sinon';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import type { Channel } from '../../src/lightning/channel/channel';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import {
	AUXILIARY_CHANNEL_DUST_LIMIT,
	MAX_AUXILIARY_HTLCS_PER_PARTY,
	validateAuxiliaryChannelType
} from '../../src/lightning/channel/auxiliary';
import {
	auxiliaryCsvPolicyError,
	createAuxiliaryOpeningCsvPolicy
} from '../../src/lightning/channel/auxiliary-csv';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryFundingDescriptor
} from '../../src/lightning/channel/auxiliary-funding';
import {
	MAX_AUXILIARY_FUNDING_DATA_BYTES,
	applyAuxiliaryFunding,
	auxiliaryCarrierError,
	validateAuxiliaryFunding
} from '../../src/lightning/channel/auxiliary-funding';
import type {
	IChannelPersistRequest,
	IChannelPersistResult
} from '../../src/lightning/channel/channel-actions';
import {
	funderCommitmentCostSats,
	signRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import type { IChannelState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isFixedAssetHtlcChannel,
	isOverlayChannel,
	isTaprootChannel,
	validateV2ChannelType
} from '../../src/lightning/channel/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	decodeAcceptChannelMessage,
	decodeOpenChannelMessage,
	encodeAcceptChannelMessage,
	encodeOpenChannelMessage
} from '../../src/lightning/message/channel-open';
import { randomBytes as engineRandomBytes } from '../../src/lightning/crypto/provider';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { MessageType } from '../../src/lightning/message/types';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	InvalidChannelOpenError,
	type IFundingProvider
} from '../../src/lightning/node/types';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import { auxiliaryChannelOpens } from '../../src/lightning/channel/auxiliary-switch';
import {
	ASSET_FUNDING_ROOT,
	hash,
	overlayChannelType,
	referenceProvider
} from './helpers/auxiliary-pair';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens
} from './helpers/auxiliary-nodes';
import { connectNodes, createNode } from './helpers/loopback-nodes';
import { configOf, seedFor } from './helpers/taproot-revoked-fixture';
import { writableState } from './helpers/writable-state';

/** What the build ships with, read before any test turns it on. */
const OPENS_AS_SHIPPED = auxiliaryChannelOpens.enabled;

const FUNDING = 2_000_000n;
/** Bob holds asset units from the start, so he is pushed the bitcoin that carries them. */
const PUSH = 500_000_000n;

const tick = async (): Promise<void> => {
	for (let i = 0; i < 12; i++) await Promise.resolve();
};
const deferred = (): {
	promise: Promise<void>;
	resolve(): void;
	reject(error: Error): void;
} => {
	let resolve!: () => void;
	let reject!: (error: Error) => void;
	const promise = new Promise<void>((ok, fail) => {
		resolve = ok;
		reject = fail;
	});
	return { promise, resolve, reject };
};

/** What one side of an opening is configured with. */
interface ISide {
	prefersTaproot?: boolean;
	/** Overrides of the asset channel config; null for a side with no provider. */
	auxiliary?: Partial<IAuxiliaryChannelConfig> | null;
	config?: Partial<IChannelManagerConfig>;
}

interface IWireMessage {
	from: 'alice' | 'bob';
	type: number;
	payload: Buffer;
}

interface IOpening {
	alice: ChannelManager;
	bob: ChannelManager;
	alicePubkey: string;
	bobPubkey: string;
	/** The asset funding as Alice, the opener, holds it. */
	descriptor: IAuxiliaryFundingDescriptor;
	/** The same funding from Bob's side. */
	incoming: IAuxiliaryFundingDescriptor;
	wire: IWireMessage[];
	errors: string[];
	/** Rewrite or drop a message before it is delivered; null drops it. */
	intercept: {
		fn?: (
			from: 'alice' | 'bob',
			type: number,
			payload: Buffer
		) => Buffer | null;
	};
	/** How many commitments each side's provider was asked to build. */
	builds: { alice: number; bob: number };
	/** Every row Bob's persistence committed, serialized. */
	durable: string[];
	/** Make Bob's persistence refuse every write from now on. */
	refuseWrites(): void;
}

const managers: ChannelManager[] = [];
const nodes: LightningNode[] = [];
const realRandomBytes = crypto.randomBytes;

/**
 * Replace the platform's randomness with a counter, the way the transcripts
 * of the previous release were captured. Restored after each test.
 */
function fixRandomness(): void {
	// The engine tests its source of randomness on first use, drawing from
	// it twice. Have that done before the counter starts.
	engineRandomBytes(1);
	let counter = 0;
	(crypto as unknown as { randomBytes: unknown }).randomBytes = (
		size: number
	): Buffer => {
		const out = Buffer.alloc(size);
		const n = counter++;
		for (let i = 0; i < size; i += 32) {
			hash(`open-golden:${n}:${i}`).copy(out, i);
		}
		return out;
	};
}

function countingProvider(count: () => void): IChannelAuxiliaryProvider {
	const provider = referenceProvider();
	return {
		...provider,
		buildCommitment(context) {
			count();
			return provider.buildCommitment(context);
		}
	};
}

function opening(
	seed: number,
	sides: { alice?: ISide; bob?: ISide } = {}
): IOpening {
	const descriptor: IAuxiliaryFundingDescriptor = {
		temporaryChannelId: hash(`asset opening temporary id ${seed}`),
		fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
		channelData: Buffer.from('proposed asset funding'),
		localBalance: 900n,
		remoteBalance: 100n
	};
	const incoming: IAuxiliaryFundingDescriptor = {
		...descriptor,
		localBalance: 100n,
		remoteBalance: 900n
	};
	const builds = { alice: 0, bob: 0 };
	const durable: string[] = [];
	let allowWrites = true;
	const configuration = (
		name: 'alice' | 'bob',
		side: ISide = {}
	): IChannelManagerConfig => ({
		...configOf(
			seedFor(name === 'alice' ? seed : seed + 1),
			side.prefersTaproot ?? false
		),
		...(name === 'bob'
			? {
					persistence: {
						persist: (
							request: IChannelPersistRequest
						): IChannelPersistResult => {
							if (!allowWrites) return { committed: false, outboxIds: [] };
							durable.push(
								JSON.stringify(
									serializeChannelState(request.channel.getFullState())
								)
							);
							return {
								committed: true,
								outboxIds:
									request.outbox?.outbound.map(
										(_message, index) => index + 1
									) ?? []
							};
						}
					}
			  }
			: {}),
		...(side.auxiliary === null
			? {}
			: {
					auxiliaryChannels: {
						provider: countingProvider(() => {
							builds[name]++;
						}),
						allowLegacyHtlcSignatures: () => true,
						resolveIncoming: (_peer: string, id: Buffer) =>
							name === 'bob' && id.equals(incoming.temporaryChannelId)
								? incoming
								: undefined,
						...side.auxiliary
					}
			  }),
		...side.config
	});
	const aliceConfig = configuration('alice', sides.alice);
	const bobConfig = configuration('bob', sides.bob);
	const alice = new ChannelManager(aliceConfig);
	const bob = new ChannelManager(bobConfig);
	managers.push(alice, bob);
	const alicePubkey = aliceConfig.localBasepoints.fundingPubkey.toString('hex');
	const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');
	const wire: IWireMessage[] = [];
	const errors: string[] = [];
	const intercept: IOpening['intercept'] = {};
	const link = (
		from: 'alice' | 'bob',
		source: ChannelManager,
		sourcePubkey: string,
		target: ChannelManager,
		targetPubkey: string
	): void => {
		source.on('error', (_id: unknown, message: unknown) => {
			errors.push(`${from}: ${String(message)}`);
		});
		source.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== targetPubkey) return;
				const delivered = intercept.fn
					? intercept.fn(from, type, payload)
					: payload;
				if (!delivered) return;
				wire.push({ from, type, payload: Buffer.from(delivered) });
				target.handleMessage(sourcePubkey, type, delivered);
			}
		);
	};
	link('alice', alice, alicePubkey, bob, bobPubkey);
	link('bob', bob, bobPubkey, alice, alicePubkey);
	return {
		alice,
		bob,
		alicePubkey,
		bobPubkey,
		descriptor,
		incoming,
		wire,
		errors,
		intercept,
		builds,
		durable,
		refuseWrites: (): void => {
			allowWrites = false;
		}
	};
}

/** Alice proposes the asset channel. */
const propose = (p: IOpening): Channel =>
	p.alice.openChannel(p.bobPubkey, FUNDING, PUSH, undefined, {
		auxiliary: p.descriptor
	});

/** Alice sends funding_created for an accepted opening. */
const fund = (p: IOpening, channel: Channel): Buffer => {
	const id = p.alice.createFunding(
		channel,
		hash('asset opening funding'),
		0,
		Buffer.alloc(64)
	);
	expect(id, p.errors.join('; ')).not.to.equal(null);
	return id!;
};

const types = (p: IOpening, from?: 'alice' | 'bob'): number[] =>
	p.wire
		.filter((message) => !from || message.from === from)
		.map((message) => message.type);

const sent = (p: IOpening, from: 'alice' | 'bob', type: number): Buffer[] =>
	p.wire
		.filter((message) => message.from === from && message.type === type)
		.map((message) => message.payload);

/** The text of every error message one side put on the wire. */
const wireErrors = (p: IOpening, from: 'alice' | 'bob'): string[] =>
	sent(p, from, MessageType.ERROR).map((payload) =>
		decodeErrorMessage(payload).data.toString()
	);

const transcript = (p: IOpening): string =>
	hash(
		Buffer.concat(
			p.wire.map((message) =>
				Buffer.concat([Buffer.from([message.type]), message.payload])
			)
		)
	).toString('hex');

/** Rewrite Alice's open_channel on its way to Bob. */
function rewriteOpen(
	p: IOpening,
	change: (
		message: ReturnType<typeof decodeOpenChannelMessage>
	) => Partial<ReturnType<typeof decodeOpenChannelMessage>>
): void {
	p.intercept.fn = (from, type, payload): Buffer => {
		if (from !== 'alice' || type !== MessageType.OPEN_CHANNEL) return payload;
		const message = decodeOpenChannelMessage(payload);
		return encodeOpenChannelMessage({ ...message, ...change(message) });
	};
}

/** Rewrite Bob's accept_channel on its way to Alice. */
function rewriteAccept(
	p: IOpening,
	change: (
		message: ReturnType<typeof decodeAcceptChannelMessage>
	) => Partial<ReturnType<typeof decodeAcceptChannelMessage>>
): void {
	p.intercept.fn = (from, type, payload): Buffer => {
		if (from !== 'bob' || type !== MessageType.ACCEPT_CHANNEL) return payload;
		const message = decodeAcceptChannelMessage(payload);
		return encodeAcceptChannelMessage({ ...message, ...change(message) });
	};
}

function simpleTaprootType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

describe('an asset channel opens over open_channel (issue #2093 step 7)', function () {
	this.timeout(20_000);
	withAssetOpens();

	afterEach(() => {
		(crypto as unknown as { randomBytes: unknown }).randomBytes =
			realRandomBytes;
		for (const manager of managers.splice(0)) manager.detachFromPeerManager();
		for (const node of nodes.splice(0)) node.destroy();
		sinon.restore();
	});

	describe('between two managers that do not prefer taproot', () => {
		it('opens with open_channel, as a taproot overlay channel, and reaches NORMAL', () => {
			const p = opening(8100);
			const channel = propose(p);
			expect(types(p)).to.deep.equal([
				MessageType.OPEN_CHANNEL,
				MessageType.ACCEPT_CHANNEL
			]);
			const proposed = decodeOpenChannelMessage(p.wire[0].payload);
			expect(proposed.temporaryChannelId).to.deep.equal(
				p.descriptor.temporaryChannelId
			);
			expect(proposed.channelType).to.deep.equal(overlayChannelType());
			expect(proposed.nextLocalNonce, 'a taproot open').to.have.length(66);
			const accepted = decodeAcceptChannelMessage(p.wire[1].payload);
			expect(accepted.channelType).to.deep.equal(overlayChannelType());
			expect(accepted.nextLocalNonce).to.have.length(66);

			const id = fund(p, channel);
			p.alice.handleFundingConfirmed(id);
			p.bob.handleFundingConfirmed(id);
			expect(types(p)).to.deep.equal([
				MessageType.OPEN_CHANNEL,
				MessageType.ACCEPT_CHANNEL,
				MessageType.FUNDING_CREATED,
				MessageType.FUNDING_SIGNED,
				MessageType.CHANNEL_READY,
				MessageType.CHANNEL_READY
			]);
			expect(p.errors).to.deep.equal([]);

			const alice = channel.getFullState();
			const bob = p.bob.getChannel(id)!.getFullState();
			for (const state of [alice, bob]) {
				expect(state.state).to.equal(ChannelState.NORMAL);
				expect(isOverlayChannel(state.channelType)).to.equal(true);
				expect(isTaprootChannel(state.channelType)).to.equal(true);
				expect(isFixedAssetHtlcChannel(state.channelType)).to.equal(false);
				expect(state.fundingTaprootMerkleRoot).to.deep.equal(
					ASSET_FUNDING_ROOT
				);
				expect(state.auxiliaryState!.openingCsvPolicy).to.equal(undefined);
			}
			expect(alice.auxiliaryState!.localBalance).to.equal(900n);
			expect(alice.auxiliaryState!.remoteBalance).to.equal(100n);
			expect(bob.auxiliaryState!.localBalance).to.equal(100n);
			expect(bob.auxiliaryState!.remoteBalance).to.equal(900n);
			expect(bob.auxiliaryState!.channelData.toString()).to.equal(
				'proposed asset funding'
			);
			expect(p.builds.alice, 'Alice built asset commitments').to.be.greaterThan(
				0
			);
			expect(p.builds.bob, 'Bob built asset commitments').to.be.greaterThan(0);
		});

		it('gives the channel the dust limit and HTLC count of an asset channel', () => {
			const loose = {
				...DEFAULT_CHANNEL_CONFIG,
				feeratePerKw: 2500,
				dustLimitSatoshis: 546n,
				maxAcceptedHtlcs: 200
			};
			const p = opening(8110, {
				alice: { config: { localConfig: loose } },
				bob: { config: { localConfig: loose } }
			});
			const channel = propose(p);
			const proposed = decodeOpenChannelMessage(p.wire[0].payload);
			const accepted = decodeAcceptChannelMessage(p.wire[1].payload);
			for (const message of [proposed, accepted]) {
				expect(message.dustLimitSatoshis).to.equal(
					AUXILIARY_CHANNEL_DUST_LIMIT
				);
				expect(message.maxAcceptedHtlcs).to.equal(
					MAX_AUXILIARY_HTLCS_PER_PARTY
				);
			}
			expect(channel.getFullState().localConfig.dustLimitSatoshis).to.equal(
				354n
			);
			expect(p.errors).to.deep.equal([]);
		});

		it('keeps a tighter dust limit and HTLC count as configured', () => {
			const tight = {
				...DEFAULT_CHANNEL_CONFIG,
				feeratePerKw: 2500,
				dustLimitSatoshis: 354n,
				maxAcceptedHtlcs: 30
			};
			const p = opening(8120, { alice: { config: { localConfig: tight } } });
			propose(p);
			const proposed = decodeOpenChannelMessage(p.wire[0].payload);
			expect(proposed.dustLimitSatoshis).to.equal(354n);
			expect(proposed.maxAcceptedHtlcs).to.equal(30);
		});

		it('funds the output of the funding key tweaked by the asset root', () => {
			const p = opening(8130);
			const channel = propose(p);
			const id = fund(p, channel);
			const state = channel.getFullState();
			const rooted = createTaprootFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints!.fundingPubkey,
				undefined,
				ASSET_FUNDING_ROOT
			).p2trOutput;
			const plain = createTaprootFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints!.fundingPubkey
			).p2trOutput;
			expect(rooted.equals(plain)).to.equal(false);
			// Both first commitments were signed and verified over that output:
			// a peer signing for the untweaked key would have been refused.
			expect(p.errors).to.deep.equal([]);
			expect(p.bob.getChannel(id)).not.to.equal(undefined);
			expect(types(p)).to.include(MessageType.FUNDING_SIGNED);
		});

		it('never sends open_channel2, and an ordinary open beside it stays ordinary', () => {
			const p = opening(8140);
			propose(p);
			const ordinary = p.alice.openChannel(p.bobPubkey, FUNDING);
			expect(types(p)).not.to.include(MessageType.OPEN_CHANNEL2);
			const state = ordinary.getFullState();
			expect(state.auxiliaryState).to.equal(undefined);
			expect(state.fundingTaprootMerkleRoot).to.equal(undefined);
			expect(isOverlayChannel(state.channelType)).to.equal(false);
			expect(isTaprootChannel(state.channelType)).to.equal(false);
			const second = decodeOpenChannelMessage(
				sent(p, 'alice', MessageType.OPEN_CHANNEL)[1]
			);
			expect(second.nextLocalNonce).to.equal(undefined);
			expect(p.errors).to.deep.equal([]);
		});
	});

	describe('an ordinary open is, on the wire, the open it was before', () => {
		// Captured from the source of the previous release (4fdaeb60) under
		// the same counter in place of the platform's randomness: every
		// message of an open to channel_ready, in order, type and payload.
		const GOLDEN = {
			staticRemoteKey:
				'98ca3b52f4488dad63a4450af55b3da69125e1873cee4d32ca3f383fc91a523f',
			simpleTaproot:
				'290a9d5153e893572581ccf85c73f7c301e48081ca84900e2a4f5b22a4816c17',
			overlayOpen:
				'84cedd24373e61cceb630a8739cef30ef1e258a1aca863a440a148ab5a1121aa',
			overlayAnswer:
				'd7f6c772d5a0c34289e28b8d0dd5ea87e44c71ddf9d60dd90a42e54ba3cf16d5' +
				'003350726f706f736564206368616e6e656c2074797065206d75737420696e63' +
				'6c756465207374617469635f72656d6f74656b6579'
		};
		/** A provider configured, and no asset funding for any open. */
		const idle: ISide = { auxiliary: { resolveIncoming: () => undefined } };

		function ordinaryOpen(
			seed: number,
			alicePrefersTaproot: boolean,
			provider: boolean,
			side: ISide = idle
		): IOpening {
			fixRandomness();
			const p = opening(seed, {
				alice: provider
					? { ...side, prefersTaproot: alicePrefersTaproot }
					: { auxiliary: null, prefersTaproot: alicePrefersTaproot },
				bob: provider ? side : { auxiliary: null }
			});
			const channel = p.alice.openChannel(p.bobPubkey, 3_000_000n);
			const txid = hash(`open golden funding ${seed}`);
			const state = channel.getFullState();
			let signature: Buffer = Buffer.alloc(64, 1);
			if (!isTaprootChannel(state.channelType)) {
				channel.setFundingOutpoint(txid, 0);
				signature = signRemoteCommitment(
					state,
					channel.getSigner()!,
					state.remoteCurrentPerCommitmentPoint!
				).signature;
			}
			const id = p.alice.createFunding(channel, txid, 0, signature)!;
			p.alice.handleFundingConfirmed(id);
			p.bob.handleFundingConfirmed(id);
			expect(p.errors).to.deep.equal([]);
			expect(channel.getFullState().state).to.equal(ChannelState.NORMAL);
			expect(p.bob.getChannel(id)!.getFullState().state).to.equal(
				ChannelState.NORMAL
			);
			return p;
		}

		for (const provider of [false, true]) {
			const who = provider
				? 'two nodes with a provider'
				: 'two nodes without a provider';
			it(`a static_remotekey open between ${who}`, () => {
				const p = ordinaryOpen(7100, false, provider);
				expect(types(p)).to.deep.equal([32, 33, 34, 35, 36, 36]);
				expect(transcript(p)).to.equal(GOLDEN.staticRemoteKey);
				expect(p.builds).to.deep.equal({ alice: 0, bob: 0 });
			});
			it(`a simple taproot open between ${who}`, () => {
				const p = ordinaryOpen(7200, true, provider);
				expect(types(p)).to.deep.equal([32, 33, 34, 35, 36, 36]);
				expect(transcript(p)).to.equal(GOLDEN.simpleTaproot);
				expect(p.builds).to.deep.equal({ alice: 0, bob: 0 });
			});
		}

		describe('with asset openings switched off, as this build ships', () => {
			withAssetOpens(false);
			it('a static_remotekey and a simple taproot open between two nodes with a provider', () => {
				expect(transcript(ordinaryOpen(7100, false, true))).to.equal(
					GOLDEN.staticRemoteKey
				);
				expect(transcript(ordinaryOpen(7200, true, true))).to.equal(
					GOLDEN.simpleTaproot
				);
			});
		});

		it('is never put to the host: a host that throws at whatever it is asked is not asked', () => {
			const asked: string[] = [];
			const fails = (name: string) => (): never => {
				asked.push(name);
				throw new Error(`host ${name} failed at /var/lib/host/secret`);
			};
			const broken: ISide = {
				auxiliary: {
					resolveIncoming: fails('resolveIncoming'),
					allowLegacyHtlcSignatures: fails('allowLegacyHtlcSignatures'),
					openingCsvPolicy: fails('openingCsvPolicy'),
					beforeAccept: fails('beforeAccept'),
					beforeFundingCreated: fails('beforeFundingCreated'),
					onAccepted: fails('onAccepted')
				}
			};
			const plain = ordinaryOpen(7100, false, true, broken);
			expect(transcript(plain)).to.equal(GOLDEN.staticRemoteKey);
			const taproot = ordinaryOpen(7200, true, true, broken);
			expect(transcript(taproot)).to.equal(GOLDEN.simpleTaproot);
			expect(asked).to.deep.equal([]);
			expect(plain.builds).to.deep.equal({ alice: 0, bob: 0 });
		});

		for (const bobPrefersTaproot of [false, true]) {
			it(`a node without a provider answers an overlay open as before (prefers taproot: ${bobPrefersTaproot})`, () => {
				// The opener's own simple taproot open_channel, its type replaced
				// by the overlay bit alone.
				const source = ordinaryOpen(7200, true, false);
				const proposed = decodeOpenChannelMessage(source.wire[0].payload);
				const payload = encodeOpenChannelMessage({
					...proposed,
					channelType: overlayChannelType()
				});
				expect(payload).to.have.length(645);
				expect(hash(payload).toString('hex')).to.equal(GOLDEN.overlayOpen);

				fixRandomness();
				const p = opening(7300, {
					alice: { auxiliary: null, prefersTaproot: true },
					bob: { auxiliary: null, prefersTaproot: bobPrefersTaproot }
				});
				const before = p.bob.nextChannelIndex;
				p.bob.handleMessage(p.alicePubkey, MessageType.OPEN_CHANNEL, payload);
				expect(p.wire.map((message) => message.type)).to.deep.equal([
					MessageType.ERROR
				]);
				expect(p.wire[0].payload.toString('hex')).to.equal(
					GOLDEN.overlayAnswer
				);
				expect(wireErrors(p, 'bob')).to.deep.equal([
					'Proposed channel type must include static_remotekey'
				]);
				expect(p.bob.nextChannelIndex).to.equal(before);
				expect(p.bob.getTempChannel(proposed.temporaryChannelId)).to.equal(
					undefined
				);
			});
		}
	});

	describe('the acceptor refuses', () => {
		function refused(p: IOpening, reason: string): void {
			expect(wireErrors(p, 'bob')).to.deep.equal([reason]);
			expect(types(p, 'bob')).to.deep.equal([MessageType.ERROR]);
			expect(p.bob.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
				undefined
			);
			expect(p.bob.listChannels()).to.have.length(0);
			expect(p.builds.bob).to.equal(0);
		}

		it('an overlay open that no asset funding was negotiated for, before it derives a key', () => {
			const p = opening(8200, {
				bob: { auxiliary: { resolveIncoming: () => undefined } }
			});
			const before = p.bob.nextChannelIndex;
			propose(p);
			refused(
				p,
				'open_channel refused: no asset funding was negotiated for this channel'
			);
			expect(p.bob.nextChannelIndex).to.equal(before);
		});

		it('nothing of an open without the overlay type for which asset funding was negotiated: it is an ordinary open', () => {
			let asked = 0;
			const p: IOpening = opening(8210, {
				bob: {
					auxiliary: {
						resolveIncoming: (_peer, id) => {
							asked++;
							return { ...p.incoming, temporaryChannelId: id };
						}
					}
				}
			});
			const channel = p.alice.openChannel(p.bobPubkey, FUNDING);
			expect(asked).to.equal(0);
			expect(wireErrors(p, 'bob')).to.deep.equal([]);
			expect(types(p)).to.deep.equal([
				MessageType.OPEN_CHANNEL,
				MessageType.ACCEPT_CHANNEL
			]);
			const accepted = p.bob.getTempChannel(channel.getTemporaryChannelId())!;
			expect(accepted.getFullState().auxiliaryState).to.equal(undefined);
			expect(accepted.getFullState().fundingTaprootMerkleRoot).to.equal(
				undefined
			);
		});

		it('an asset opening its host fails on, and tells the peer nothing of why', () => {
			const p = opening(8215, {
				bob: {
					auxiliary: {
						resolveIncoming: () => {
							throw new Error('negotiation store at /var/lib/host is down');
						}
					}
				}
			});
			const before = p.bob.nextChannelIndex;
			propose(p);
			refused(
				p,
				'open_channel refused: the asset channel could not be accepted'
			);
			expect(p.errors).to.include(
				'bob: open_channel refused: negotiation store at /var/lib/host is down'
			);
			expect(p.bob.nextChannelIndex).to.equal(before);
			for (const hook of ['openingCsvPolicy', 'allowLegacyHtlcSignatures']) {
				const q = opening(8216, {
					bob: {
						auxiliary: {
							[hook]: () => {
								throw new Error(`${hook} read /var/lib/host and failed`);
							}
						}
					}
				});
				propose(q);
				refused(
					q,
					'open_channel refused: the asset channel could not be accepted'
				);
				expect(q.errors).to.include(
					`bob: open_channel refused: ${hook} read /var/lib/host and failed`
				);
			}
		});

		it('funding the host describes badly', () => {
			const p = opening(8220, {
				bob: {
					auxiliary: {
						resolveIncoming: (_peer, id) => ({
							temporaryChannelId: id,
							fundingTaprootMerkleRoot: Buffer.alloc(31, 1),
							channelData: Buffer.from('x'),
							localBalance: 1n,
							remoteBalance: 1n
						})
					}
				}
			});
			propose(p);
			// What the host got wrong is this node's to know, not the peer's.
			refused(
				p,
				'open_channel refused: the asset channel could not be accepted'
			);
			expect(p.errors).to.include(
				'bob: open_channel refused: Invalid asset funding identity'
			);
		});

		it('funding described for another temporary id', () => {
			const p = opening(8225, {
				bob: {
					auxiliary: {
						resolveIncoming: () => ({
							temporaryChannelId: hash('some other opening'),
							fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
							channelData: Buffer.from('x'),
							localBalance: 1n,
							remoteBalance: 1n
						})
					}
				}
			});
			propose(p);
			refused(
				p,
				'open_channel refused: the asset channel could not be accepted'
			);
			expect(p.errors).to.include(
				'bob: open_channel refused: Invalid asset funding identity'
			);
		});

		it('an overlay open while asset openings are switched off, without asking the host', () => {
			let asked = 0;
			const p: IOpening = opening(8226, {
				bob: {
					auxiliary: {
						resolveIncoming: () => {
							asked++;
							return p.incoming;
						}
					}
				}
			});
			const before = p.bob.nextChannelIndex;
			// Held back: Alice proposes as a peer whose build has them on would.
			let proposed: Buffer | undefined;
			p.intercept.fn = (from, type, payload): Buffer | null => {
				if (from !== 'alice' || type !== MessageType.OPEN_CHANNEL) {
					return payload;
				}
				proposed = payload;
				return null;
			};
			propose(p);
			auxiliaryChannelOpens.enabled = false;
			try {
				p.bob.handleMessage(p.alicePubkey, MessageType.OPEN_CHANNEL, proposed!);
			} finally {
				auxiliaryChannelOpens.enabled = true;
			}
			refused(p, 'open_channel refused: asset channels are not enabled');
			expect(asked).to.equal(0);
			expect(p.bob.nextChannelIndex).to.equal(before);
		});

		it('an opening whose bitcoin, after the fee and anchors its opener pays, leaves a holder of asset units no output', () => {
			const config = configOf(seedFor(1), false).localConfig!;
			const cost = funderCommitmentCostSats(
				config.feeratePerKw,
				0,
				overlayChannelType()
			);
			const dust = AUXILIARY_CHANNEL_DUST_LIMIT;
			// The opener keeps exactly the dust limit after the fee and anchors.
			const edge = (FUNDING - cost - dust) * 1000n;
			const good = opening(8228);
			const channel = good.alice.openChannel(
				good.bobPubkey,
				FUNDING,
				edge,
				undefined,
				{ auxiliary: good.descriptor }
			);
			fund(good, channel);
			expect(good.errors).to.deep.equal([]);
			expect(types(good, 'bob')).to.deep.equal([
				MessageType.ACCEPT_CHANNEL,
				MessageType.FUNDING_SIGNED
			]);

			// One millisatoshi more pushed rounds the opener's side down a
			// satoshi. Its own check refuses that, so the open_channel is put
			// to Bob as a peer without the check would send it.
			const p = opening(8229);
			const before = p.bob.nextChannelIndex;
			rewriteOpen(p, () => ({ pushMsat: edge + 1n }));
			expect(() =>
				p.alice.openChannel(p.bobPubkey, FUNDING, edge + 1n, undefined, {
					auxiliary: p.descriptor
				})
			).to.throw(
				`The opener of an asset channel holds asset units and has to keep at least ${dust} satoshis, after the ${cost} of the commitment fee and anchors, to carry them`
			);
			p.alice.openChannel(p.bobPubkey, FUNDING, edge, undefined, {
				auxiliary: p.descriptor
			});
			refused(
				p,
				`open_channel refused: The opener of an asset channel holds asset units and has to keep at least ${dust} satoshis, after the ${cost} of the commitment fee and anchors, to carry them`
			);
			expect(p.bob.nextChannelIndex).to.equal(before);
		});

		it('an opening whose dust limit would trim the output that carries its own asset units', () => {
			const p = opening(8231);
			const before = p.bob.nextChannelIndex;
			// Bob is pushed 500 satoshis in this opening.
			rewriteOpen(p, () => ({ dustLimitSatoshis: 501n }));
			p.alice.openChannel(p.bobPubkey, FUNDING, 500_000n, undefined, {
				auxiliary: p.descriptor
			});
			refused(
				p,
				'open_channel refused: The acceptor of an asset channel holds asset units and has to be pushed at least 501 satoshis to carry them'
			);
			expect(p.bob.nextChannelIndex).to.equal(before);
		});

		it('an opening that asks for the asset channel to be announced', () => {
			const p = opening(8233);
			const before = p.bob.nextChannelIndex;
			// Alice's own opening never sets announce_channel, so it is put to
			// Bob as a peer that sets it would send it.
			rewriteOpen(p, (message) => ({
				channelFlags: message.channelFlags | 0x01
			}));
			p.alice.openChannel(p.bobPubkey, FUNDING, PUSH, undefined, {
				auxiliary: p.descriptor
			});
			refused(
				p,
				`open_channel refused: An asset channel does not support an announcement (channel ${p.descriptor.temporaryChannelId.toString(
					'hex'
				)})`
			);
			expect(p.bob.nextChannelIndex).to.equal(before);
		});

		it('an opening that pushes it no bitcoin to carry its asset units', () => {
			const p = opening(8227);
			const before = p.bob.nextChannelIndex;
			p.alice.openChannel(p.bobPubkey, FUNDING, 353_999n, undefined, {
				auxiliary: { ...p.descriptor, remoteBalance: 0n }
			});
			refused(
				p,
				'open_channel refused: The acceptor of an asset channel holds asset units and has to be pushed at least 354 satoshis to carry them'
			);
			expect(p.bob.nextChannelIndex).to.equal(before);
		});

		it('an opening in the older HTLC mode from a peer it was not allowed for', () => {
			const p = opening(8230, {
				bob: { auxiliary: { allowLegacyHtlcSignatures: () => false } }
			});
			propose(p);
			refused(
				p,
				'open_channel refused: New asset channels require fixed HTLC outputs or explicit peer compatibility'
			);
		});

		it('a type that claims fixed HTLC outputs the two never negotiated', () => {
			const p = opening(8240);
			rewriteOpen(p, () => ({
				channelType: overlayChannelType(Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS)
			}));
			propose(p);
			expect(wireErrors(p, 'bob')).to.deep.equal([
				'open_channel refused: Fixed asset HTLC outputs were not mutually negotiated'
			]);
			expect(p.bob.listChannels()).to.have.length(0);
		});

		it('a type that claims child custody the two never selected', () => {
			const p = opening(8245);
			rewriteOpen(p, () => ({
				channelType: overlayChannelType(Feature.OPTION_ASSET_CHILD_CUSTODY)
			}));
			propose(p);
			expect(wireErrors(p, 'bob')).to.deep.equal([
				'open_channel refused: Asset child custody mode was not mutually selected'
			]);
			expect(p.bob.listChannels()).to.have.length(0);
		});

		it('an overlay type with a bit beside it that an asset channel cannot have, and gives the key index back', () => {
			const p = opening(8250);
			rewriteOpen(p, () => ({
				channelType: overlayChannelType(Feature.ANCHOR_ZERO_FEE_HTLC)
			}));
			const before = p.bob.nextChannelIndex;
			propose(p);
			expect(wireErrors(p, 'bob')).to.deep.equal([
				'Invalid Taproot overlay channel type'
			]);
			expect(p.bob.listChannels()).to.have.length(0);
			expect(p.bob.nextChannelIndex).to.equal(before);
		});

		it('an opener that would hold it to more HTLCs than an asset channel carries', () => {
			const p = opening(8260);
			rewriteOpen(p, () => ({ maxAcceptedHtlcs: 84 }));
			const before = p.bob.nextChannelIndex;
			propose(p);
			expect(wireErrors(p, 'bob')).to.deep.equal([
				'Asset channel max accepted HTLCs exceeds 83'
			]);
			expect(p.bob.listChannels()).to.have.length(0);
			expect(p.bob.nextChannelIndex).to.equal(before);
		});

		it('open_channel2 of the overlay type, which is not a dual-funded type', () => {
			expect(validateV2ChannelType(overlayChannelType())).to.equal(
				'channel_type is not a recognized dual-funded (v2) combination'
			);
			expect(
				validateV2ChannelType(
					overlayChannelType(Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS)
				)
			).to.equal(
				'channel_type is not a recognized dual-funded (v2) combination'
			);
		});
	});

	describe('while asset openings are switched off', () => {
		withAssetOpens(false);

		it('is no longer how this build ships: openings are on', () => {
			expect(OPENS_AS_SHIPPED).to.equal(true);
		});

		it('refuses to open an asset channel before it derives a key or sends anything, and opens any other', () => {
			const p = opening(8900);
			const before = p.alice.nextChannelIndex;
			expect(() => propose(p)).to.throw(
				'Asset channels are not enabled in this build'
			);
			expect(p.alice.nextChannelIndex).to.equal(before);
			expect(p.wire).to.have.length(0);
			p.alice.openChannel(p.bobPubkey, FUNDING);
			expect(types(p)).to.deep.equal([
				MessageType.OPEN_CHANNEL,
				MessageType.ACCEPT_CHANNEL
			]);
		});

		it('refuses through the node, naming nothing it did not make', () => {
			const alice = assetHost('aux-switched-off', 1);
			const bob = assetHost('aux-switched-off', 2);
			nodes.push(alice.node, bob.node);
			connectHosts(alice, bob);
			expect(() =>
				alice.node.openAuxiliaryChannel(
					bob.node.getNodeId(),
					FUNDING,
					{
						temporaryChannelId: hash('switched off'),
						fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
						channelData: Buffer.from('x'),
						localBalance: 900n,
						remoteBalance: 100n
					},
					PUSH
				)
			).to.throw('Asset channels are not enabled in this build');
			expect(alice.node.listChannels()).to.have.length(0);
			expect(alice.errors).to.deep.equal([]);
		});
	});

	describe('between nodes that store their channels in SQLite', () => {
		it('opens without a storage error, and each row is the asset channel its node holds', async () => {
			const alice = assetHost('aux-sqlite-open', 1, {}, { sqlite: true });
			const bob = assetHost('aux-sqlite-open', 2, {}, { sqlite: true });
			nodes.push(alice.node, bob.node);
			connectHosts(alice, bob);
			const channelId = await openAssetChannel(alice, bob, {
				tag: 'sqlite open',
				openerUnits: 900n,
				acceptorUnits: 100n
			});
			expect(alice.errors).to.deep.equal([]);
			expect(bob.errors).to.deep.equal([]);
			expect(alice.broadcasts).to.have.length(1);
			const rowOf = (host: typeof alice): IChannelState => {
				expect(host.storage!.loadAllChannels()).to.have.length(1);
				return host.storage!.loadChannel(channelId.toString('hex'))!.state;
			};
			const opener = rowOf(alice);
			expect(opener.state).to.equal(ChannelState.NORMAL);
			// The funding data the host set last, at funding, is what is stored.
			expect(opener.auxiliaryState!.channelData.toString()).to.equal(
				'final funding proofs'
			);
			expect(opener.auxiliaryState!.localBalance).to.equal(900n);
			expect(opener.auxiliaryState!.remoteBalance).to.equal(100n);
			expect(opener.fundingTaprootMerkleRoot).to.deep.equal(ASSET_FUNDING_ROOT);
			const acceptor = rowOf(bob);
			expect(acceptor.state).to.equal(ChannelState.NORMAL);
			expect(acceptor.auxiliaryState!.localBalance).to.equal(100n);
			expect(acceptor.auxiliaryState!.remoteBalance).to.equal(900n);
		});
	});

	describe('the opener refuses, before it derives a key or sends anything', () => {
		function refusedToOpen(
			p: IOpening,
			descriptor: IAuxiliaryFundingDescriptor,
			reason: string
		): void {
			const before = p.alice.nextChannelIndex;
			expect(() =>
				p.alice.openChannel(p.bobPubkey, FUNDING, PUSH, undefined, {
					auxiliary: descriptor
				})
			).to.throw(reason);
			expect(p.alice.nextChannelIndex).to.equal(before);
			expect(p.wire).to.have.length(0);
			expect(p.alice.listChannels()).to.have.length(0);
		}

		it('without a provider', () => {
			const p = opening(8300, { alice: { auxiliary: null } });
			refusedToOpen(p, p.descriptor, 'Asset channel provider is required');
		});

		it('funding with a temporary id of zeros, a short root, no balance, or a balance past a u64', () => {
			const p = opening(8310);
			refusedToOpen(
				p,
				{ ...p.descriptor, temporaryChannelId: Buffer.alloc(32) },
				'Invalid asset funding identity'
			);
			refusedToOpen(
				p,
				{ ...p.descriptor, fundingTaprootMerkleRoot: Buffer.alloc(31, 1) },
				'Invalid asset funding identity'
			);
			refusedToOpen(
				p,
				{ ...p.descriptor, localBalance: 0n, remoteBalance: 0n },
				'Invalid asset funding balances'
			);
			refusedToOpen(
				p,
				{ ...p.descriptor, localBalance: -1n, remoteBalance: 5n },
				'Invalid asset funding balances'
			);
			refusedToOpen(
				p,
				{
					...p.descriptor,
					localBalance: 0xffffffffffffffffn,
					remoteBalance: 1n
				},
				'Invalid asset funding balances'
			);
		});

		it('an asset balance that no bitcoin output would carry', () => {
			const p = opening(8315);
			const before = p.alice.nextChannelIndex;
			const feeratePerKw = configOf(seedFor(1), false).localConfig!
				.feeratePerKw;
			const cost = funderCommitmentCostSats(
				feeratePerKw,
				0,
				overlayChannelType()
			);
			expect(() =>
				p.alice.openChannel(p.bobPubkey, FUNDING, 0n, undefined, {
					auxiliary: p.descriptor
				})
			).to.throw(
				'The acceptor of an asset channel holds asset units and has to be pushed at least 354 satoshis to carry them'
			);
			expect(() =>
				p.alice.openChannel(p.bobPubkey, FUNDING, FUNDING * 1000n, undefined, {
					auxiliary: p.descriptor
				})
			).to.throw(
				`The opener of an asset channel holds asset units and has to keep at least 354 satoshis, after the ${cost} of the commitment fee and anchors, to carry them`
			);
			expect(p.alice.nextChannelIndex).to.equal(before);
			expect(p.wire).to.have.length(0);
			const carrier = (
				pushMsat: bigint,
				openerAssetBalance: bigint,
				acceptorAssetBalance: bigint,
				dustLimitSatoshis = 354n
			): string | undefined =>
				auxiliaryCarrierError({
					fundingSatoshis: FUNDING,
					pushMsat,
					feeratePerKw,
					openerAssetBalance,
					acceptorAssetBalance,
					dustLimitSatoshis
				});
			// All of the assets on one side need no output for the other.
			expect(carrier(0n, 1000n, 0n)).to.equal(undefined);
			expect(carrier(FUNDING * 1000n, 0n, 5n)).to.equal(undefined);
			expect(carrier(354_000n, 1n, 1n)).to.equal(undefined);
			// The opener pays the fee and the anchors out of its side, and a
			// fraction of a satoshi pushed is a satoshi it does not have.
			const edge = (FUNDING - cost - 354n) * 1000n;
			expect(carrier(edge, 1n, 1n)).to.equal(undefined);
			expect(carrier(edge + 1n, 1n, 1n)).to.match(/^The opener of an asset/);
			expect(carrier(edge + 1n, 0n, 1n)).to.equal(undefined);
			// A higher dust limit, the peer's, moves both edges.
			expect(carrier(499_999n, 1n, 1n, 500n)).to.match(
				/^The acceptor of an asset channel .* at least 500 satoshis/
			);
			expect(carrier(500_000n, 1n, 1n, 500n)).to.equal(undefined);
		});

		it('an accept_channel whose dust limit would trim the output that carries its own asset units', () => {
			const p = opening(8317);
			rewriteAccept(p, () => ({ dustLimitSatoshis: 501n }));
			const channel = p.alice.openChannel(
				p.bobPubkey,
				FUNDING,
				500_000n,
				undefined,
				{ auxiliary: p.descriptor }
			);
			expect(wireErrors(p, 'alice')).to.deep.equal([
				'The acceptor of an asset channel holds asset units and has to be pushed at least 501 satoshis to carry them'
			]);
			expect(p.alice.getTempChannel(channel.getTemporaryChannelId())).to.equal(
				undefined
			);
		});

		it('the older HTLC mode toward a peer the host has not allowed it for', () => {
			const p = opening(8320, {
				alice: { auxiliary: { allowLegacyHtlcSignatures: () => false } }
			});
			refusedToOpen(
				p,
				p.descriptor,
				'New asset channels require fixed HTLC outputs or explicit peer compatibility'
			);
		});

		it('a temporary id that an opening of its own already uses', () => {
			const p = opening(8330);
			propose(p);
			const before = p.alice.nextChannelIndex;
			const sentBefore = p.wire.length;
			expect(() => propose(p)).to.throw(
				'Temporary channel id is already in use'
			);
			expect(p.alice.nextChannelIndex).to.equal(before);
			expect(p.wire).to.have.length(sentBefore);
		});
	});

	describe('a provider that refuses the first commitment', () => {
		const refusing = (): IChannelAuxiliaryProvider => ({
			...referenceProvider(),
			buildCommitment: (): never => {
				throw new Error('funding proofs unavailable');
			}
		});

		it('ends the opening at the opener, by name, with nothing sent for the funding', () => {
			const p = opening(8350, {
				alice: { auxiliary: { provider: refusing() } }
			});
			const channel = propose(p);
			const temporaryId = p.descriptor.temporaryChannelId;
			expect(() =>
				p.alice.createFunding(
					channel,
					hash('asset opening funding'),
					0,
					Buffer.alloc(64)
				)
			).to.throw(
				`Asset channel funding failed (channel ${temporaryId.toString(
					'hex'
				)}): funding proofs unavailable`
			);
			expect(types(p)).not.to.include(MessageType.FUNDING_CREATED);
			expect(wireErrors(p, 'alice')).to.deep.equal([
				'Asset channel funding failed'
			]);
			expect(p.alice.getTempChannel(temporaryId)).to.equal(undefined);
			expect(p.bob.getTempChannel(temporaryId)).to.equal(undefined);
		});

		it('ends the opening at the acceptor, by name, and tells the opener', () => {
			const p = opening(8360, {
				bob: { auxiliary: { provider: refusing() } }
			});
			const channel = propose(p);
			const temporaryId = p.descriptor.temporaryChannelId;
			p.alice.createFunding(
				channel,
				hash('asset opening funding'),
				0,
				Buffer.alloc(64)
			);
			expect(types(p)).not.to.include(MessageType.FUNDING_SIGNED);
			expect(wireErrors(p, 'bob')).to.deep.equal([
				'Asset channel funding failed'
			]);
			expect(
				p.errors.filter((error) => error.startsWith('bob: '))
			).to.deep.equal([
				`bob: Asset channel funding failed (channel ${temporaryId.toString(
					'hex'
				)}): funding proofs unavailable`
			]);
			expect(p.bob.getTempChannel(temporaryId)).to.equal(undefined);
			expect(p.bob.listChannels()).to.have.length(0);
		});
	});

	describe('the opener refuses an accept_channel', () => {
		function aborted(p: IOpening, reason: string): void {
			expect(wireErrors(p, 'alice')).to.deep.equal([reason]);
			expect(p.alice.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
				undefined
			);
			expect(types(p)).not.to.include(MessageType.FUNDING_CREATED);
		}

		it('of another channel type', () => {
			const p = opening(8400);
			rewriteAccept(p, () => ({ channelType: simpleTaprootType() }));
			propose(p);
			aborted(p, 'Asset channel requires the Taproot overlay channel type');
		});

		it('that would hold it to more HTLCs than an asset channel carries', () => {
			const p = opening(8410);
			rewriteAccept(p, () => ({ maxAcceptedHtlcs: 84 }));
			propose(p);
			aborted(p, 'Asset channel max accepted HTLCs exceeds 83');
		});
	});

	describe('the CSV policy of an opening', () => {
		const policy = (
			minimumDelay?: number,
			maximumDelay?: number,
			preferredDelay?: number
		): Partial<IAuxiliaryChannelConfig> => ({
			openingCsvPolicy: () => ({
				mode: 'symmetric',
				...(minimumDelay === undefined ? {} : { minimumDelay }),
				...(maximumDelay === undefined ? {} : { maximumDelay }),
				...(preferredDelay === undefined ? {} : { preferredDelay })
			})
		});

		it('leaves the configured delays alone when the host sets none', () => {
			const p = opening(8500);
			const channel = propose(p);
			const id = fund(p, channel);
			for (const state of [
				channel.getFullState(),
				p.bob.getChannel(id)!.getFullState()
			]) {
				expect(state.localConfig.toSelfDelay).to.equal(144);
				expect(state.remoteConfig.toSelfDelay).to.equal(144);
				expect(state.auxiliaryState!.openingCsvPolicy).to.equal(undefined);
			}
		});

		it('has the acceptor answer with the delay the opener proposed', () => {
			const p = opening(8510, {
				alice: { auxiliary: policy(144, 2016, 432) },
				bob: { auxiliary: policy() }
			});
			const channel = propose(p);
			expect(decodeOpenChannelMessage(p.wire[0].payload).toSelfDelay).to.equal(
				432
			);
			expect(
				decodeAcceptChannelMessage(p.wire[1].payload).toSelfDelay
			).to.equal(432);
			const id = fund(p, channel);
			p.alice.handleFundingConfirmed(id);
			p.bob.handleFundingConfirmed(id);
			expect(p.errors).to.deep.equal([]);
			const alice = channel.getFullState();
			const bob = p.bob.getChannel(id)!.getFullState();
			expect(alice.state).to.equal(ChannelState.NORMAL);
			expect(alice.auxiliaryState!.openingCsvPolicy).to.deep.equal({
				mode: 'symmetric',
				minimumDelay: 144,
				maximumDelay: 2016,
				localDelay: 432
			});
			expect(bob.auxiliaryState!.openingCsvPolicy).to.deep.equal({
				mode: 'symmetric',
				minimumDelay: 144,
				maximumDelay: 2016,
				localDelay: 432
			});
			// The policy is part of the stored channel.
			expect(p.durable[p.durable.length - 1]).to.include('"localDelay":432');
		});

		it('has the acceptor refuse a delay outside its range, before it derives a key', () => {
			const p = opening(8520, {
				alice: { auxiliary: policy(144, 2016, 432) },
				bob: { auxiliary: policy(144, 288) }
			});
			const before = p.bob.nextChannelIndex;
			propose(p);
			expect(wireErrors(p, 'bob')).to.deep.equal([
				'open_channel refused: Asset channel CSV delay 432 is outside the permitted range 144..288'
			]);
			expect(p.bob.nextChannelIndex).to.equal(before);
			expect(p.bob.listChannels()).to.have.length(0);
		});

		it('has the opener refuse an accept that answers with another delay', () => {
			const p = opening(8530, {
				alice: { auxiliary: policy(144, 2016, 432) }
			});
			propose(p);
			expect(wireErrors(p, 'alice')).to.deep.equal([
				'Asset channel requires symmetric CSV delays: local 432, remote 144; a new opening is required'
			]);
			expect(p.alice.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
				undefined
			);
		});

		it('never lets a policy reduce the configured delay', () => {
			const p = opening(8540, { alice: { auxiliary: policy(100) } });
			const before = p.alice.nextChannelIndex;
			expect(() => propose(p)).to.throw(
				'Asset channel CSV policy cannot reduce configured protection'
			);
			expect(p.alice.nextChannelIndex).to.equal(before);
			expect(p.wire).to.have.length(0);
		});

		it('chooses and checks a delay as a pure function of the policy', () => {
			expect(createAuxiliaryOpeningCsvPolicy(undefined, 144)).to.equal(
				undefined
			);
			expect(
				createAuxiliaryOpeningCsvPolicy({ mode: 'symmetric' }, 144)
			).to.deep.equal({
				mode: 'symmetric',
				minimumDelay: 144,
				maximumDelay: 2016,
				localDelay: 144
			});
			expect(() =>
				createAuxiliaryOpeningCsvPolicy(
					{ mode: 'symmetric', minimumDelay: 300, maximumDelay: 200 },
					144
				)
			).to.throw('Invalid asset channel CSV opening policy');
			expect(() =>
				createAuxiliaryOpeningCsvPolicy({ mode: 'symmetric' }, 144, 2017)
			).to.throw('outside the permitted range 144..2016');
			const state = createAuxiliaryOpeningCsvPolicy(
				{ mode: 'symmetric', preferredDelay: 200 },
				144
			)!;
			expect(auxiliaryCsvPolicyError(undefined, 144, 720)).to.equal(undefined);
			expect(auxiliaryCsvPolicyError(state, 200, 200)).to.equal(undefined);
			expect(auxiliaryCsvPolicyError(state, 144, 200)).to.equal(
				'Asset channel advertised CSV delay changed'
			);
			expect(auxiliaryCsvPolicyError(state, 200, 100)).to.equal(
				'Asset channel CSV delay 100 is outside the permitted range 144..2016'
			);
			expect(auxiliaryCsvPolicyError(state, 200, 201)).to.equal(
				'Asset channel requires symmetric CSV delays: local 200, remote 201; a new opening is required'
			);
		});
	});

	describe('the host validates an opening before the node goes on', () => {
		const accepts = (p: IOpening): number =>
			sent(p, 'bob', MessageType.ACCEPT_CHANNEL).length;
		const signed = (p: IOpening): number =>
			sent(p, 'bob', MessageType.FUNDING_SIGNED).length;
		const created = (p: IOpening): Buffer =>
			sent(p, 'alice', MessageType.FUNDING_CREATED)[0];

		it('holds accept_channel and the first signature until each check passes, and runs each check once', async () => {
			const accept = deferred();
			const funding = deferred();
			let acceptChecks = 0;
			let fundingChecks = 0;
			const p: IOpening = opening(8600, {
				bob: {
					auxiliary: {
						beforeAccept: async () => {
							acceptChecks++;
							await accept.promise;
						},
						beforeFundingCreated: async () => {
							fundingChecks++;
							await funding.promise;
							p.bob.setAuxiliaryFundingData(
								p.alicePubkey,
								p.descriptor.temporaryChannelId,
								Buffer.from('verified funding proofs')
							);
						}
					}
				}
			});
			const channel = propose(p);
			await tick();
			expect(acceptChecks).to.equal(1);
			expect(accepts(p)).to.equal(0);
			accept.resolve();
			await tick();
			expect(accepts(p)).to.equal(1);

			const id = fund(p, channel);
			for (let i = 0; i < 64; i++) {
				p.bob.handleMessage(
					p.alicePubkey,
					MessageType.FUNDING_CREATED,
					Buffer.from(created(p))
				);
			}
			await tick();
			expect(fundingChecks).to.equal(1);
			expect(p.builds.bob, 'nothing built before the check').to.equal(0);
			expect(signed(p)).to.equal(0);
			funding.resolve();
			await tick();
			expect(signed(p)).to.equal(1);
			expect(
				p.durable.some((row) =>
					row.includes(Buffer.from('verified funding proofs').toString('hex'))
				),
				'the verified funding data is stored'
			).to.equal(true);
			expect(
				p.bob
					.getChannel(id)!
					.getFullState()
					.auxiliaryState!.channelData.toString()
			).to.equal('verified funding proofs');
			expect(p.errors).to.deep.equal([]);
		});

		it('does not gate an ordinary open', async () => {
			let checks = 0;
			const p = opening(8610, {
				bob: {
					auxiliary: {
						resolveIncoming: () => undefined,
						beforeAccept: async () => {
							checks++;
						},
						beforeFundingCreated: async () => {
							checks++;
						}
					}
				}
			});
			const channel = p.alice.openChannel(p.bobPubkey, FUNDING);
			// Synchronously answered, as an open without a provider is.
			expect(accepts(p)).to.equal(1);
			const txid = hash('ordinary funding beside a gate');
			channel.setFundingOutpoint(txid, 0);
			const state = channel.getFullState();
			const { signature } = signRemoteCommitment(
				state,
				channel.getSigner()!,
				state.remoteCurrentPerCommitmentPoint!
			);
			p.alice.createFunding(channel, txid, 0, signature);
			expect(signed(p)).to.equal(1);
			await tick();
			expect(checks).to.equal(0);
			expect(p.errors).to.deep.equal([]);
		});

		it('aborts when the same step arrives again with other bytes, and a late pass signs nothing', async () => {
			const funding = deferred();
			const p = opening(8620, {
				bob: { auxiliary: { beforeFundingCreated: () => funding.promise } }
			});
			fund(p, propose(p));
			await tick();
			const conflict = Buffer.from(created(p));
			conflict[32] ^= 1;
			p.bob.handleMessage(p.alicePubkey, MessageType.FUNDING_CREATED, conflict);
			expect(p.bob.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
				undefined
			);
			funding.resolve();
			await tick();
			expect(p.builds.bob).to.equal(0);
			expect(signed(p)).to.equal(0);
		});

		it('aborts a check that takes longer than two minutes', async () => {
			const clock = sinon.useFakeTimers();
			const funding = deferred();
			const p = opening(8630, {
				bob: { auxiliary: { beforeFundingCreated: () => funding.promise } }
			});
			fund(p, propose(p));
			await tick();
			await clock.tickAsync(120_001);
			expect(p.bob.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
				undefined
			);
			expect(wireErrors(p, 'bob')).to.deep.equal([
				'Asset funding validation failed'
			]);
			funding.resolve();
			await tick();
			expect(p.builds.bob).to.equal(0);
			expect(signed(p)).to.equal(0);
		});

		it('leaves no timer and signs nothing once the manager is detached', async () => {
			const clock = sinon.useFakeTimers();
			const funding = deferred();
			const p = opening(8640, {
				bob: { auxiliary: { beforeFundingCreated: () => funding.promise } }
			});
			fund(p, propose(p));
			await tick();
			p.bob.detachFromPeerManager();
			expect(clock.countTimers()).to.equal(0);
			funding.resolve();
			await tick();
			expect(signed(p)).to.equal(0);
		});

		it('never sends the accept, and its keys, of an opening whose check fails', async () => {
			const accept = deferred();
			const p = opening(8650, {
				bob: { auxiliary: { beforeAccept: () => accept.promise } }
			});
			propose(p);
			await tick();
			accept.reject(new Error('negotiation store unavailable'));
			await tick();
			expect(accepts(p)).to.equal(0);
			expect(wireErrors(p, 'bob')).to.deep.equal([
				'Asset funding validation failed'
			]);
			expect(p.bob.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
				undefined
			);
		});

		it('answers an opening the peer proposed again after a disconnect, while the first was still being checked', async () => {
			const checks: Array<ReturnType<typeof deferred>> = [];
			const p = opening(8655, {
				bob: {
					auxiliary: {
						beforeAccept: () => {
							const check = deferred();
							checks.push(check);
							return check.promise;
						}
					}
				}
			});
			propose(p);
			await tick();
			expect(checks).to.have.length(1);
			const first = p.bob.getTempChannel(p.descriptor.temporaryChannelId)!;
			const proposed = sent(p, 'alice', MessageType.OPEN_CHANNEL)[0];
			// The connection drops and comes back; the peer proposes again.
			p.bob.handlePeerDisconnected(p.alicePubkey);
			p.bob.handleMessage(p.alicePubkey, MessageType.OPEN_CHANNEL, proposed);
			await tick();
			const second = p.bob.getTempChannel(p.descriptor.temporaryChannelId)!;
			expect(second).not.to.equal(undefined);
			expect(second).not.to.equal(first);
			expect(checks, 'the host is asked about the new opening').to.have.length(
				2
			);
			expect(accepts(p)).to.equal(0);
			// The first check ends, late: it is nobody's now and answers nothing.
			checks[0].resolve();
			await tick();
			expect(accepts(p)).to.equal(0);
			checks[1].resolve();
			await tick();
			expect(accepts(p)).to.equal(1);
			expect(wireErrors(p, 'bob')).to.deep.equal([]);
			expect(p.bob.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
				second
			);
		});

		it('withholds the first signature when the row cannot be stored', async () => {
			const funding = deferred();
			const p = opening(8660, {
				bob: { auxiliary: { beforeFundingCreated: () => funding.promise } }
			});
			fund(p, propose(p));
			await tick();
			p.refuseWrites();
			funding.resolve();
			await tick();
			expect(signed(p)).to.equal(0);
		});

		it('refuses more checks at once than it has room for', async () => {
			const never = deferred();
			const p: IOpening = opening(8670, {
				bob: {
					auxiliary: {
						resolveIncoming: (_peer, id) => ({
							...p.incoming,
							temporaryChannelId: id
						}),
						beforeAccept: () => never.promise
					}
				}
			});
			const aborted: string[] = [];
			p.bob.on('channel:aborted', (_id: unknown, reason: unknown) => {
				aborted.push(String(reason));
			});
			// One peer may hold four opens pending, so the openings arrive
			// from many: the same open_channel, as each of them would send it.
			const peerOf = (index: number): string =>
				getPublicKey(hash(`a peer with an opening ${index}`)).toString('hex');
			let from = 0;
			p.intercept.fn = (_side, type, payload): Buffer | null => {
				if (type === MessageType.OPEN_CHANNEL) {
					p.bob.handleMessage(peerOf(from), type, payload);
				}
				return null;
			};
			for (from = 0; from < 65; from++) {
				p.alice.openChannel(p.bobPubkey, FUNDING, PUSH, undefined, {
					auxiliary: {
						...p.descriptor,
						temporaryChannelId: hash(`opening ${from} of many`)
					}
				});
			}
			await tick();
			expect(aborted).to.deep.equal([
				'Asset funding validation capacity exceeded'
			]);
			expect(p.bob.getTempChannel(hash('opening 64 of many'))).to.equal(
				undefined
			);
			expect(p.bob.getTempChannel(hash('opening 63 of many'))).not.to.equal(
				undefined
			);
		});
	});

	describe('the asset funding data of an opening', () => {
		it('can be replaced until the first signature, and not after', () => {
			const p = opening(8700);
			const channel = propose(p);
			const temporaryId = p.descriptor.temporaryChannelId;
			p.alice.setAuxiliaryFundingData(
				p.bobPubkey,
				temporaryId,
				Buffer.from('final funding proofs')
			);
			expect(
				channel.getFullState().auxiliaryState!.channelData.toString()
			).to.equal('final funding proofs');
			p.bob.setAuxiliaryFundingData(
				p.alicePubkey,
				temporaryId,
				Buffer.from('final funding proofs')
			);
			// A channel has no row before it has a channel id.
			expect(p.durable).to.have.length(0);

			expect(() =>
				p.alice.setAuxiliaryFundingData(
					p.alicePubkey,
					temporaryId,
					Buffer.from('x')
				)
			).to.throw('Asset funding peer or channel mismatch');
			expect(() =>
				p.alice.setAuxiliaryFundingData(
					p.bobPubkey,
					hash('no such opening'),
					Buffer.from('x')
				)
			).to.throw('Asset funding peer or channel mismatch');
			expect(() =>
				p.alice.setAuxiliaryFundingData(
					p.bobPubkey,
					temporaryId,
					Buffer.alloc(0)
				)
			).to.throw('Invalid asset funding data size');

			const id = fund(p, channel);
			expect(p.durable.length).to.be.greaterThan(0);
			expect(
				p.durable.every((row) =>
					row.includes(Buffer.from('final funding proofs').toString('hex'))
				),
				'every stored row carries the replacement'
			).to.equal(true);
			expect(() =>
				p.alice.setAuxiliaryFundingData(p.bobPubkey, id, Buffer.from('late'))
			).to.throw('Asset funding peer or channel mismatch');
			expect(() =>
				p.alice.setAuxiliaryFundingData(
					p.bobPubkey,
					temporaryId,
					Buffer.from('late')
				)
			).to.throw(/Asset funding/);
			expect(
				channel.getFullState().auxiliaryState!.channelData.toString()
			).to.equal('final funding proofs');
		});

		it('is not accepted for an ordinary opening', () => {
			const p = opening(8710, {
				bob: { auxiliary: { resolveIncoming: () => undefined } }
			});
			const channel = p.alice.openChannel(p.bobPubkey, FUNDING);
			expect(() =>
				p.alice.setAuxiliaryFundingData(
					p.bobPubkey,
					channel.getTemporaryChannelId(),
					Buffer.from('x')
				)
			).to.throw('Asset funding data is already committed');
			expect(channel.getFullState().auxiliaryState).to.equal(undefined);
		});
	});

	describe('the asset HTLC mode of a new channel', () => {
		const features = (...set: number[]): FeatureFlags => {
			const flags = FeatureFlags.empty();
			for (const feature of set) flags.setOptional(feature);
			return flags;
		};
		const OVERLAY = Feature.OPTION_TAPROOT_OVERLAY;
		const FIXED = Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS;
		const CUSTODY = Feature.OPTION_ASSET_CHILD_CUSTODY;
		const PEER = '02' + 'ab'.repeat(32);

		/** A manager that sees one connected peer with the given features. */
		function managerSeeing(
			local: FeatureFlags,
			remote: FeatureFlags | null,
			auxiliary: Partial<IAuxiliaryChannelConfig> = {},
			fixedFees?: boolean
		): ChannelManager {
			const manager = new ChannelManager({
				...configOf(seedFor(8800), false),
				localFeatures: local,
				auxiliaryChannels: {
					provider: referenceProvider(),
					resolveIncoming: () => undefined,
					...auxiliary
				}
			});
			managers.push(manager);
			(manager as unknown as { peerManager: unknown }).peerManager = {
				getPeer: (pubkey: string) =>
					pubkey === PEER && remote
						? { getRemoteInit: () => ({ features: remote }) }
						: undefined
			};
			if (fixedFees !== undefined) {
				manager.setFundingProvider({
					supportsFixedOutputFees: () => fixedFees
				} as unknown as IFundingProvider);
			}
			return manager;
		}

		it('is the older mode only where the host allows it for the peer', () => {
			const allowed: string[] = [];
			const manager = managerSeeing(features(OVERLAY), features(OVERLAY), {
				allowLegacyHtlcSignatures: (peer) => {
					allowed.push(peer);
					return true;
				}
			});
			expect(manager.getAuxiliaryHtlcMode(PEER)).to.equal('legacy');
			expect(allowed).to.deep.equal([PEER]);
			expect(() =>
				managerSeeing(
					features(OVERLAY),
					features(OVERLAY)
				).getAuxiliaryHtlcMode(PEER)
			).to.throw(
				'New asset channels require fixed HTLC outputs or explicit peer compatibility'
			);
		});

		it('is fixed outputs when both advertise them and the wallet can prepare their fees', () => {
			const both = features(OVERLAY, FIXED);
			expect(
				managerSeeing(both, both, {}, true).getAuxiliaryHtlcMode(PEER)
			).to.equal('fixed');
			expect(() =>
				managerSeeing(both, both, {}, false).getAuxiliaryHtlcMode(PEER)
			).to.throw(
				'Fixed asset HTLC outputs require durable bounded fee preparation'
			);
			expect(() =>
				managerSeeing(both, both).getAuxiliaryHtlcMode(PEER)
			).to.throw(
				'Fixed asset HTLC outputs require durable bounded fee preparation'
			);
			// One side alone advertising them is the older mode.
			expect(
				managerSeeing(both, features(OVERLAY), {
					allowLegacyHtlcSignatures: () => true
				}).getAuxiliaryHtlcMode(PEER)
			).to.equal('legacy');
		});

		it('needs both sides to advertise asset channels, and a connected peer', () => {
			const legacy = { allowLegacyHtlcSignatures: (): boolean => true };
			expect(() =>
				managerSeeing(
					features(OVERLAY),
					features(Feature.OPTION_TAPROOT),
					legacy
				).getAuxiliaryHtlcMode(PEER)
			).to.throw('Peer did not advertise asset channels');
			expect(() =>
				managerSeeing(
					features(Feature.OPTION_TAPROOT),
					features(OVERLAY),
					legacy
				).getAuxiliaryHtlcMode(PEER)
			).to.throw('This node does not advertise asset channels');
			expect(() =>
				managerSeeing(features(OVERLAY), null, legacy).getAuxiliaryHtlcMode(
					PEER
				)
			).to.throw('Not connected to peer');
		});

		it('answers a policy that asks for the mode, without asking the policy again', () => {
			const asked: string[] = [];
			const seen: string[] = [];
			const holder: { manager?: ChannelManager } = {};
			const manager = managerSeeing(features(OVERLAY), features(OVERLAY), {
				allowLegacyHtlcSignatures: () => true,
				openingCsvPolicy: (peer) => {
					asked.push(peer);
					// A host that sets its delays by the mode of the channel.
					seen.push(holder.manager!.getAuxiliaryHtlcMode(peer));
					return undefined;
				}
			});
			holder.manager = manager;
			expect(manager.getAuxiliaryHtlcMode(PEER)).to.equal('legacy');
			expect(asked).to.deep.equal([PEER]);
			expect(seen).to.deep.equal(['legacy']);
			// The guard is per read: the next one consults the policy again,
			// and a policy that throws still refuses the read.
			expect(manager.getAuxiliaryHtlcMode(PEER)).to.equal('legacy');
			expect(asked).to.deep.equal([PEER, PEER]);
			const refusing = managerSeeing(features(OVERLAY), features(OVERLAY), {
				allowLegacyHtlcSignatures: () => true,
				openingCsvPolicy: () => {
					throw new Error('no delay for this peer');
				}
			});
			expect(() => refusing.getAuxiliaryHtlcMode(PEER)).to.throw(
				'no delay for this peer'
			);
			expect(() => refusing.getAuxiliaryHtlcMode(PEER)).to.throw(
				'no delay for this peer'
			);
		});

		it('needs a provider that can build the capsule before child custody is selected', () => {
			const all = features(OVERLAY, FIXED, CUSTODY);
			expect(() =>
				managerSeeing(
					all,
					all,
					{ allowRevokedChildCustody: true },
					true
				).getAuxiliaryHtlcMode(PEER)
			).to.throw('Child custody requires an asset recovery capsule provider');
			// Not selected by the host: fixed outputs without it.
			expect(
				managerSeeing(all, all, {}, true).getAuxiliaryHtlcMode(PEER)
			).to.equal('fixed');
		});

		it('is refused without a provider', () => {
			const manager = new ChannelManager(configOf(seedFor(8810), false));
			managers.push(manager);
			expect(() => manager.getAuxiliaryHtlcMode(PEER)).to.throw(
				'Asset channel provider is required'
			);
		});
	});

	describe('the pure rules of an opening', () => {
		const descriptor = (): IAuxiliaryFundingDescriptor => ({
			temporaryChannelId: hash('pure rules'),
			fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
			channelData: Buffer.from('x'),
			localBalance: 1n,
			remoteBalance: 0n
		});

		it('bounds the asset funding data', () => {
			expect(() => validateAuxiliaryFunding(descriptor())).not.to.throw();
			expect(() =>
				validateAuxiliaryFunding({
					...descriptor(),
					channelData: Buffer.alloc(MAX_AUXILIARY_FUNDING_DATA_BYTES + 1)
				})
			).to.throw('Asset funding data exceeds limit');
			expect(() =>
				validateAuxiliaryFunding({
					...descriptor(),
					channelData: 'x' as unknown as Buffer
				})
			).to.throw('Asset funding data exceeds limit');
		});

		it('applies funding only to the channel it was described for', () => {
			const p = opening(8900, {
				bob: { auxiliary: { resolveIncoming: () => undefined } }
			});
			const channel = p.alice.openChannel(p.bobPubkey, FUNDING);
			const state = { ...channel.getFullState() };
			expect(() => applyAuxiliaryFunding(state, descriptor())).to.throw(
				'Invalid asset funding identity'
			);
			expect(state.auxiliaryState).to.equal(undefined);
			expect(state.fundingTaprootMerkleRoot).to.equal(undefined);
		});

		it('judges the type of a channel that holds asset funding, and no other', () => {
			const p = opening(8910);
			const asset = propose(p).getFullState();
			expect(
				validateAuxiliaryChannelType(asset, overlayChannelType())
			).to.equal(null);
			expect(
				validateAuxiliaryChannelType(
					asset,
					overlayChannelType(
						Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS,
						Feature.OPTION_ASSET_CHILD_CUSTODY,
						Feature.SCID_ALIAS,
						Feature.ZERO_CONF
					)
				)
			).to.equal(null);
			expect(
				validateAuxiliaryChannelType(
					asset,
					overlayChannelType(Feature.OPTION_ASSET_CHILD_CUSTODY)
				)
			).to.equal('Child custody requires fixed asset HTLC outputs');
			expect(validateAuxiliaryChannelType(asset, simpleTaprootType())).to.equal(
				'Asset channel requires the Taproot overlay channel type'
			);
			expect(validateAuxiliaryChannelType(asset, undefined)).to.equal(
				'Asset channel requires the Taproot overlay channel type'
			);
			expect(
				validateAuxiliaryChannelType(
					asset,
					Buffer.concat([Buffer.alloc(1), overlayChannelType()])
				)
			).to.equal('Asset channel requires the Taproot overlay channel type');
			const ordinary = p.alice.openChannel(p.bobPubkey, FUNDING).getFullState();
			expect(
				validateAuxiliaryChannelType(ordinary, simpleTaprootType())
			).to.equal(null);
			expect(
				validateAuxiliaryChannelType(ordinary, overlayChannelType())
			).to.equal(null);
		});
	});

	describe('through the node', () => {
		interface INodePair {
			alice: LightningNode;
			bob: LightningNode;
			descriptor: IAuxiliaryFundingDescriptor;
			accepted: Array<{ channel: Channel; peer: string }>;
			built: number;
			broadcasts: string[];
			wire: Array<{ from: 'alice' | 'bob'; type: number }>;
		}

		/** What a peer that runs asset channels advertises. */
		const assetPeerFeatures = (): FeatureFlags => {
			const flags = FeatureFlags.empty();
			flags.setOptional(Feature.STATIC_REMOTE_KEY);
			flags.setOptional(Feature.OPTION_TAPROOT);
			flags.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
			return flags;
		};

		/**
		 * Two nodes joined by their message events, with no connection of
		 * their own. A node refuses an asset opening when it cannot read what
		 * its peer advertised, so each is told here, in place of the init its
		 * own networking would have read; `null` leaves a node with nothing
		 * to read.
		 */
		function nodePair(
			tag: string,
			seen: {
				alice?: FeatureFlags | null;
				bob?: FeatureFlags | null;
			} = {}
		): INodePair {
			const descriptor: IAuxiliaryFundingDescriptor = {
				temporaryChannelId: hash(`node asset opening ${tag}`),
				fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
				channelData: Buffer.from('proposed asset funding'),
				localBalance: 900n,
				remoteBalance: 100n
			};
			const pair: INodePair = {
				descriptor,
				accepted: [],
				built: 0,
				broadcasts: [],
				wire: []
			} as unknown as INodePair;
			const fundingProvider = (): IFundingProvider =>
				({
					buildFundingTransaction: async () => {
						pair.built++;
						throw new Error('an asset channel is funded by the host');
					},
					broadcastTransaction: async (txHex: string) => {
						pair.broadcasts.push(txHex);
						return 'broadcast';
					}
				}) as unknown as IFundingProvider;
			pair.alice = createNode(tag, 1, undefined, {
				fundingProvider: fundingProvider(),
				auxiliaryChannels: {
					provider: referenceProvider(),
					allowLegacyHtlcSignatures: () => true,
					resolveIncoming: () => undefined,
					onAccepted: (channel, peer) => {
						pair.accepted.push({ channel, peer });
					}
				}
			});
			pair.bob = createNode(tag, 2, undefined, {
				auxiliaryChannels: {
					provider: referenceProvider(),
					allowLegacyHtlcSignatures: () => true,
					resolveIncoming: (_peer, id) =>
						id.equals(descriptor.temporaryChannelId)
							? { ...descriptor, localBalance: 100n, remoteBalance: 900n }
							: undefined
				}
			});
			nodes.push(pair.alice, pair.bob);
			for (const [from, node] of [
				['alice', pair.alice],
				['bob', pair.bob]
			] as const) {
				node.on('message:outbound', (_peer: string, type: number) => {
					pair.wire.push({ from, type });
				});
				const features =
					seen[from] === undefined ? assetPeerFeatures() : seen[from];
				if (features) {
					(
						node as unknown as {
							peerInitFeatures: (peer: string) => FeatureFlags | undefined;
						}
					).peerInitFeatures = (): FeatureFlags => features;
				}
			}
			connectNodes(pair.alice, pair.bob);
			return pair;
		}

		/** A signed transaction paying `script` the channel's funding amount. */
		function fundingTx(script: Buffer, signed = true): bitcoin.Transaction {
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(hash('asset funding input'), 0);
			if (signed) tx.setWitness(0, [Buffer.alloc(64, 7)]);
			tx.addOutput(Buffer.from('6a', 'hex'), 0);
			tx.addOutput(script, Number(FUNDING));
			return tx;
		}

		function fundingScripts(channel: Channel): {
			rooted: Buffer;
			plain: Buffer;
		} {
			const state = channel.getFullState();
			return {
				rooted: createTaprootFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints!.fundingPubkey,
					undefined,
					ASSET_FUNDING_ROOT
				).p2trOutput,
				plain: createTaprootFundingScript(
					state.localBasepoints.fundingPubkey,
					state.remoteBasepoints!.fundingPubkey
				).p2trOutput
			};
		}

		it('opens an asset channel that the host funds, and broadcasts its funding once the peer has signed', async () => {
			const p = nodePair('aux-node-open');
			const channel = p.alice.openAuxiliaryChannel(
				p.bob.getNodeId(),
				FUNDING,
				p.descriptor,
				PUSH
			);
			expect(p.wire).to.deep.equal([
				{ from: 'alice', type: MessageType.OPEN_CHANNEL },
				{ from: 'bob', type: MessageType.ACCEPT_CHANNEL }
			]);
			// The host is handed the accepted channel; the wallet is not asked
			// to build a funding transaction for it.
			expect(p.accepted).to.have.length(1);
			expect(p.accepted[0].channel).to.equal(channel);
			expect(p.accepted[0].peer).to.equal(p.bob.getNodeId());
			await tick();
			expect(p.built).to.equal(0);
			expect(p.alice.getAuxiliaryHtlcMode(p.bob.getNodeId())).to.equal(
				'legacy'
			);

			const { rooted, plain } = fundingScripts(channel);
			const temporaryId = p.descriptor.temporaryChannelId;
			const peer = p.bob.getNodeId();
			const data = Buffer.from('final funding proofs');
			expect(() =>
				p.alice.fundAuxiliaryChannel(
					peer,
					temporaryId,
					fundingTx(plain).toHex(),
					1,
					data
				)
			).to.throw(
				'Asset funding transaction does not match the negotiated output'
			);
			expect(() =>
				p.alice.fundAuxiliaryChannel(
					peer,
					temporaryId,
					fundingTx(rooted).toHex(),
					0,
					data
				)
			).to.throw(
				'Asset funding transaction does not match the negotiated output'
			);
			expect(() =>
				p.alice.fundAuxiliaryChannel(
					peer,
					temporaryId,
					fundingTx(rooted, false).toHex(),
					1,
					data
				)
			).to.throw('Asset funding transaction is not fully signed');
			// An input whose signature sits in its scriptSig leaves the txid
			// open to change; so does a scriptSig that is not a witness program.
			const legacy = fundingTx(rooted, false);
			legacy.setInputScript(0, Buffer.alloc(107, 0x30));
			const mixed = fundingTx(rooted);
			mixed.setInputScript(0, Buffer.alloc(23, 0x51));
			const second = fundingTx(rooted);
			second.addInput(hash('a second, legacy input'), 1);
			second.setInputScript(1, Buffer.alloc(107, 0x30));
			for (const tx of [legacy, mixed, second]) {
				expect(() =>
					p.alice.fundAuxiliaryChannel(peer, temporaryId, tx.toHex(), 1, data)
				).to.throw(
					`Asset funding transaction has an input that is not segwit (channel ${temporaryId.toString(
						'hex'
					)})`
				);
			}
			expect(() =>
				p.alice.fundAuxiliaryChannel(peer, temporaryId, 'zz', 1, data)
			).to.throw('Asset funding transaction cannot be parsed');
			expect(() =>
				p.alice.fundAuxiliaryChannel(
					p.alice.getNodeId(),
					temporaryId,
					fundingTx(rooted).toHex(),
					1,
					data
				)
			).to.throw('Asset funding peer or channel mismatch');
			expect(p.wire).to.have.length(2);
			expect(p.broadcasts).to.have.length(0);

			const tx = fundingTx(rooted);
			const channelId = p.alice.fundAuxiliaryChannel(
				peer,
				temporaryId,
				tx.toHex(),
				1,
				data
			);
			expect(p.wire.slice(2)).to.deep.equal([
				{ from: 'alice', type: MessageType.FUNDING_CREATED },
				{ from: 'bob', type: MessageType.FUNDING_SIGNED }
			]);
			await tick();
			expect(p.broadcasts).to.deep.equal([tx.toHex()]);
			expect(p.built).to.equal(0);
			const state = channel.getFullState();
			expect(state.fundingTxid).to.deep.equal(tx.getHash());
			expect(state.fundingOutputIndex).to.equal(1);
			expect(state.auxiliaryState!.channelData).to.deep.equal(data);

			p.alice.handleFundingConfirmed(channelId);
			p.bob.handleFundingConfirmed(channelId);
			const alice = p.alice.getAuxiliaryChannelInfo(channelId)!;
			const bob = p.bob.getAuxiliaryChannelInfo(channelId)!;
			expect(alice.state).to.equal(ChannelState.NORMAL);
			expect(bob.state).to.equal(ChannelState.NORMAL);
			expect(alice.peerPubkey).to.equal(p.bob.getNodeId());
			expect(alice.channelId).to.deep.equal(channelId);
			expect(alice.temporaryChannelId).to.deep.equal(temporaryId);
			expect(alice.localAssetBalance).to.equal(900n);
			expect(alice.remoteAssetBalance).to.equal(100n);
			expect(bob.localAssetBalance).to.equal(100n);
			expect(bob.remoteAssetBalance).to.equal(900n);
			expect(alice.dustLimitSatoshis).to.equal(354n);
			expect(alice.localBalanceMsat + alice.remoteBalanceMsat).to.equal(
				FUNDING * 1000n
			);
		});

		it('names the channel when it refuses a funding, and ends an opening the host could not take on', () => {
			const p = nodePair('aux-node-named');
			const temporaryId = p.descriptor.temporaryChannelId;
			expect(() =>
				p.alice.fundAuxiliaryChannel(
					p.bob.getNodeId(),
					temporaryId,
					'00',
					0,
					Buffer.from('x')
				)
			).to.throw(
				`Asset funding peer or channel mismatch (channel ${temporaryId.toString(
					'hex'
				)})`
			);

			const aborted: string[] = [];
			p.alice.on('channel:aborted', (_id: unknown, reason: unknown) => {
				aborted.push(String(reason));
			});
			(
				p.alice as unknown as {
					auxiliaryChannels: IAuxiliaryChannelConfig;
				}
			).auxiliaryChannels.onAccepted = (): never => {
				throw new Error('asset wallet is locked');
			};
			p.alice.openAuxiliaryChannel(
				p.bob.getNodeId(),
				FUNDING,
				p.descriptor,
				PUSH
			);
			expect(p.wire.map((message) => message.type)).to.deep.equal([
				MessageType.OPEN_CHANNEL,
				MessageType.ACCEPT_CHANNEL,
				MessageType.ERROR
			]);
			expect(aborted).to.deep.equal(['Asset channel funding failed']);
			expect(() =>
				p.alice.fundAuxiliaryChannel(
					p.bob.getNodeId(),
					temporaryId,
					'00',
					0,
					Buffer.from('x')
				)
			).to.throw('Asset funding peer or channel mismatch');
		});

		it('drops a funding transaction the peer was never sent', () => {
			const p = nodePair('aux-node-dropped');
			const channel = p.alice.openAuxiliaryChannel(
				p.bob.getNodeId(),
				FUNDING,
				p.descriptor,
				PUSH
			);
			const internals = p.alice as unknown as {
				pendingFundingTxs: Map<string, unknown>;
				auxiliaryChannels: IAuxiliaryChannelConfig;
			};
			// The provider turns the first commitment down at funding time.
			writableState(channel).auxiliaryProvider = {
				...referenceProvider(),
				buildCommitment: (): never => {
					throw new Error('funding proofs unavailable');
				}
			};
			const tx = fundingTx(fundingScripts(channel).rooted);
			expect(() =>
				p.alice.fundAuxiliaryChannel(
					p.bob.getNodeId(),
					p.descriptor.temporaryChannelId,
					tx.toHex(),
					1,
					Buffer.from('final funding proofs')
				)
			).to.throw(
				`Asset channel funding failed (channel ${p.descriptor.temporaryChannelId.toString(
					'hex'
				)}): funding proofs unavailable`
			);
			expect(internals.pendingFundingTxs.size).to.equal(0);
			expect(p.broadcasts).to.have.length(0);
			expect(p.wire.map((message) => message.type)).to.deep.equal([
				MessageType.OPEN_CHANNEL,
				MessageType.ACCEPT_CHANNEL,
				MessageType.ERROR
			]);
		});

		it('says nothing of a channel that is not an asset channel', () => {
			const p = nodePair('aux-node-info');
			expect(p.alice.getAuxiliaryChannelInfo(hash('no channel'))).to.equal(
				undefined
			);
		});

		it('broadcasts through the chain backend for a node that has no wallet to fund from', async () => {
			const p = nodePair('aux-node-backend');
			const sentBy: string[] = [];
			const internals = p.alice as unknown as {
				fundingProvider: unknown;
				_chainBackend: unknown;
			};
			internals.fundingProvider = null;
			internals._chainBackend = {
				broadcastTransaction: async (txHex: string) => {
					sentBy.push(txHex);
					return 'broadcast';
				}
			};
			const channel = p.alice.openAuxiliaryChannel(
				p.bob.getNodeId(),
				FUNDING,
				p.descriptor,
				PUSH
			);
			const tx = fundingTx(fundingScripts(channel).rooted);
			p.alice.fundAuxiliaryChannel(
				p.bob.getNodeId(),
				p.descriptor.temporaryChannelId,
				tx.toHex(),
				1,
				Buffer.from('final funding proofs')
			);
			await tick();
			expect(sentBy).to.deep.equal([tx.toHex()]);
			expect(p.broadcasts).to.have.length(0);
		});

		it('refuses to open when what the peer advertised cannot be read, or says no asset channels', () => {
			const unread = nodePair('aux-node-unread', { alice: null });
			expect(() =>
				unread.alice.openAuxiliaryChannel(
					unread.bob.getNodeId(),
					FUNDING,
					unread.descriptor,
					PUSH
				)
			).to.throw('Asset channel peer features cannot be read');
			expect(() =>
				unread.alice.getAuxiliaryHtlcMode(unread.bob.getNodeId())
			).to.throw('Asset channel peer features cannot be read');
			expect(unread.wire).to.have.length(0);

			const ordinary = FeatureFlags.empty();
			ordinary.setOptional(Feature.STATIC_REMOTE_KEY);
			ordinary.setOptional(Feature.OPTION_TAPROOT);
			const plain = nodePair('aux-node-plain-peer', { alice: ordinary });
			expect(() =>
				plain.alice.openAuxiliaryChannel(
					plain.bob.getNodeId(),
					FUNDING,
					plain.descriptor,
					PUSH
				)
			).to.throw('Peer did not advertise asset channels');
			expect(plain.wire).to.have.length(0);
		});

		it('refuses an inbound asset opening when what the opener advertised cannot be read, or says no asset channels', () => {
			const ordinary = FeatureFlags.empty();
			ordinary.setOptional(Feature.STATIC_REMOTE_KEY);
			for (const [tag, seen, reason] of [
				[
					'aux-node-unread-in',
					null,
					'open_channel refused: Asset channel peer features cannot be read'
				],
				[
					'aux-node-plain-in',
					ordinary,
					'open_channel refused: Peer did not advertise asset channels'
				]
			] as const) {
				const p = nodePair(tag, { bob: seen });
				const answers: string[] = [];
				p.bob.on(
					'message:outbound',
					(_peer: string, type: number, payload: Buffer) => {
						if (type === MessageType.ERROR) {
							answers.push(decodeErrorMessage(payload).data.toString());
						}
					}
				);
				p.alice.openAuxiliaryChannel(
					p.bob.getNodeId(),
					FUNDING,
					p.descriptor,
					PUSH
				);
				expect(answers).to.deep.equal([reason]);
				expect(p.wire.map((message) => message.type)).to.deep.equal([
					MessageType.OPEN_CHANNEL,
					MessageType.ERROR
				]);
				expect(p.bob.getChannelManager().listChannels()).to.have.length(0);
				expect(p.accepted).to.have.length(0);
			}
		});

		it('opens over a real connection, where each node reads what the other advertised from its init', async function () {
			this.timeout(30_000);
			const descriptor: IAuxiliaryFundingDescriptor = {
				temporaryChannelId: hash('asset opening over a real connection'),
				fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
				channelData: Buffer.from('proposed asset funding'),
				localBalance: 900n,
				remoteBalance: 100n
			};
			const accepted: Channel[] = [];
			const broadcasts: string[] = [];
			const until = async (
				what: string,
				condition: () => boolean
			): Promise<void> => {
				for (let i = 0; i < 1000 && !condition(); i++) {
					await new Promise((resolve) => setTimeout(resolve, 10));
				}
				expect(condition(), what).to.equal(true);
			};
			const listen = async (node: LightningNode): Promise<number> => {
				await node.listen(0, '127.0.0.1');
				return (
					node.getPeerManager() as unknown as {
						server: { address(): { port: number } };
					}
				).server.address().port;
			};
			const alice = createNode('aux-node-real', 1, undefined, {
				enableNetworking: true,
				fundingProvider: {
					buildFundingTransaction: async () => {
						throw new Error('an asset channel is funded by the host');
					},
					broadcastTransaction: async (txHex: string) => {
						broadcasts.push(txHex);
						return 'broadcast';
					}
				} as unknown as IFundingProvider,
				auxiliaryChannels: {
					provider: referenceProvider(),
					allowLegacyHtlcSignatures: () => true,
					resolveIncoming: () => undefined,
					onAccepted: (channel) => {
						accepted.push(channel);
					}
				}
			});
			const bob = createNode('aux-node-real', 2, undefined, {
				enableNetworking: true,
				auxiliaryChannels: {
					provider: referenceProvider(),
					allowLegacyHtlcSignatures: () => true,
					resolveIncoming: (_peer, id) =>
						id.equals(descriptor.temporaryChannelId)
							? { ...descriptor, localBalance: 100n, remoteBalance: 900n }
							: undefined
				}
			});
			const plain = createNode('aux-node-real', 3, undefined, {
				enableNetworking: true
			});
			nodes.push(alice, bob, plain);
			for (const node of [alice, bob, plain]) node.on('node:error', () => {});

			// The channel manager of a networked node has its peer manager from
			// construction, and reads each peer's init through it.
			expect(alice.getPeerManager()).to.not.equal(null);
			await alice.connectPeer(bob.getNodeId(), '127.0.0.1', await listen(bob));
			await alice.connectPeer(
				plain.getNodeId(),
				'127.0.0.1',
				await listen(plain)
			);
			await until(
				'both inits read',
				() =>
					!!alice.getPeerManager()!.getPeer(bob.getNodeId())?.getRemoteInit() &&
					!!alice.getPeerManager()!.getPeer(plain.getNodeId())?.getRemoteInit()
			);

			// A peer without a provider does not advertise the overlay.
			expect(() =>
				alice.openAuxiliaryChannel(
					plain.getNodeId(),
					FUNDING,
					{ ...descriptor, temporaryChannelId: hash('to a plain peer') },
					PUSH
				)
			).to.throw('Peer did not advertise asset channels');
			expect(alice.getAuxiliaryHtlcMode(bob.getNodeId())).to.equal('legacy');

			const channel = alice.openAuxiliaryChannel(
				bob.getNodeId(),
				FUNDING,
				descriptor,
				PUSH
			);
			await until('the peer accepts', () => accepted.length === 1);
			expect(accepted[0]).to.equal(channel);
			const tx = fundingTx(fundingScripts(channel).rooted);
			const channelId = alice.fundAuxiliaryChannel(
				bob.getNodeId(),
				descriptor.temporaryChannelId,
				tx.toHex(),
				1,
				Buffer.from('final funding proofs')
			);
			await until('the funding is broadcast', () => broadcasts.length === 1);
			expect(broadcasts).to.deep.equal([tx.toHex()]);
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			await until(
				'both sides are open',
				() =>
					alice.getAuxiliaryChannelInfo(channelId)?.state ===
						ChannelState.NORMAL &&
					bob.getAuxiliaryChannelInfo(channelId)?.state === ChannelState.NORMAL
			);
			expect(
				bob.getAuxiliaryChannelInfo(channelId)!.localAssetBalance
			).to.equal(100n);
			expect(isOverlayChannel(channel.getFullState().channelType)).to.equal(
				true
			);
		});

		it('refuses to open without a provider, without a broadcaster, or with a push above the funding', () => {
			const plain = createNode('aux-node-plain', 1);
			const peer = createNode('aux-node-plain', 2);
			nodes.push(plain, peer);
			connectNodes(plain, peer);
			const descriptor: IAuxiliaryFundingDescriptor = {
				temporaryChannelId: hash('refused node opening'),
				fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
				channelData: Buffer.from('x'),
				localBalance: 1n,
				remoteBalance: 0n
			};
			expect(() =>
				plain.openAuxiliaryChannel(peer.getNodeId(), FUNDING, descriptor)
			)
				.to.throw(InvalidChannelOpenError)
				.with.property(
					'message',
					'An auxiliary channel provider is required to open an asset channel'
				);
			expect(() => plain.getAuxiliaryHtlcMode(peer.getNodeId())).to.throw(
				'Asset channel provider is required'
			);

			const p = nodePair('aux-node-refusals');
			expect(() =>
				p.alice.openAuxiliaryChannel(
					p.bob.getNodeId(),
					FUNDING,
					p.descriptor,
					FUNDING * 1000n + 1n
				)
			).to.throw(InvalidChannelOpenError);
			expect(() =>
				p.alice.openAuxiliaryChannel('nonsense', FUNDING, p.descriptor)
			).to.throw(InvalidChannelOpenError);
			expect(() =>
				p.alice.openAuxiliaryChannel(p.bob.getNodeId(), 0n, p.descriptor)
			).to.throw(InvalidChannelOpenError);
			(p.alice as unknown as { fundingProvider: unknown }).fundingProvider =
				null;
			expect(() =>
				p.alice.openAuxiliaryChannel(p.bob.getNodeId(), FUNDING, p.descriptor)
			)
				.to.throw(InvalidChannelOpenError)
				.with.property(
					'message',
					'Asset channel funding requires a transaction broadcaster'
				);
			expect(p.wire).to.have.length(0);
		});

		it('sends open_channel to a peer that negotiated dual funding, where an ordinary open goes to open_channel2', () => {
			const p = nodePair('aux-node-dual-fund');
			const peer = p.bob.getNodeId();
			const remote = FeatureFlags.empty();
			remote.setOptional(Feature.STATIC_REMOTE_KEY);
			remote.setOptional(Feature.DUAL_FUND);
			remote.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
			const internals = p.alice as unknown as {
				peerManager: unknown;
				openChannelV2: unknown;
			};
			internals.peerManager = {
				getPeer: (pubkey: string) =>
					pubkey === peer
						? { getRemoteInit: () => ({ features: remote }) }
						: undefined,
				destroy: (): void => {}
			};
			const v2: bigint[] = [];
			internals.openChannelV2 = (
				_pubkey: string,
				params: { fundingSatoshis: bigint }
			): { v2: boolean } => {
				v2.push(params.fundingSatoshis);
				return { v2: true };
			};

			p.alice.openChannel(peer, 100_000n);
			expect(v2, 'an ordinary open is dual-funded').to.deep.equal([100_000n]);
			expect(p.wire).to.have.length(0);

			const channel = p.alice.openAuxiliaryChannel(
				peer,
				FUNDING,
				p.descriptor,
				PUSH
			);
			expect(v2, 'the asset open is not').to.have.length(1);
			expect(p.wire.map((message) => message.type)).to.deep.equal([
				MessageType.OPEN_CHANNEL,
				MessageType.ACCEPT_CHANNEL
			]);
			expect(isOverlayChannel(channel.getFullState().channelType)).to.equal(
				true
			);
		});
	});
});
