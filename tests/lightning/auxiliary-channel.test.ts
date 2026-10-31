import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import { buildAuxiliaryJusticePackage } from '../../src/lightning/watchtower/auxiliary';
import {
	matchAuxiliaryJusticeChild,
	buildAuxiliaryChildRemedy
} from '../../src/lightning/watchtower/auxiliary-child';
import {
	childRevocationBasepoint,
	acceptChildRevocationRecord,
	CHILD_REVOCATION_RECORD
} from '../../src/lightning/channel/child-revocation';
import { isRevokedChildCustodyChannel } from '../../src/lightning/channel/types';
import {
	applyAuxiliaryClose,
	auxiliaryClosingRelayProfile
} from '../../src/lightning/channel/auxiliary-close';
import {
	encodeInitMessage,
	decodeInitMessage
} from '../../src/lightning/message/init';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	createNode,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';
import { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { MessageType } from '../../src/lightning/message/types';
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { IAuxiliaryFundingDescriptor } from '../../src/lightning/channel/auxiliary-funding';
import { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	isOverlayChannel,
	isTaprootChannel,
	isFixedAssetHtlcChannel
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	Feature,
	FeatureFlags,
	hasUnsupportedRequiredFeatures
} from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	classifyOutputs,
	resolveOurCommitmentOutputs,
	resolveRevokedSecondLevelOutput
} from '../../src/lightning/chain/output-resolver';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
import {
	derivePrivateKey,
	derivePublicKey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	retainFundingEpoch,
	selectFundingEpoch
} from '../../src/lightning/channel/funding-state';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { taprootCommitmentSighash } from '../../src/lightning/channel/commitment-musig';
import { verifyRemoteHtlcSignaturesTaproot } from '../../src/lightning/channel/commitment-builder';
import {
	deserializeChannelState,
	serializeChannelState,
	deserializeChainMonitorState,
	serializeChainMonitorState
} from '../../src/lightning/storage/serialization';
import {
	encodeUpdateAddHtlcMessage,
	decodeUpdateAddHtlcMessage
} from '../../src/lightning/message/channel-update';
import {
	encodeCommitmentSignedMessage,
	decodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import {
	encodeShutdownMessage,
	decodeShutdownMessage,
	decodeClosingSignedMessage
} from '../../src/lightning/message/channel-close';
import { COMMIT_ALL } from './helpers/channel-persistence';
import {
	MonitorState,
	CommitmentType,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';

bitcoin.initEccLib(ecc);
const hash = (value: Buffer | string): Buffer =>
	crypto.createHash('sha256').update(value).digest();
const amountRecord = (amount: bigint): Map<bigint, Buffer> => {
	const value = Buffer.alloc(8);
	value.writeBigUInt64BE(amount);
	return new Map([[65536n, value]]);
};
const leafFor = (value: string) => ({
	script: bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, hash(value)])
});

function provider(): IChannelAuxiliaryProvider {
	return {
		buildCommitment(context) {
			const outputLeaves = new Map();
			const secondLevelLeaves = new Map();
			for (const output of context.outputs) {
				if (output.role.startsWith('anchor_')) continue;
				const balance =
					output.role === 'to_local'
						? context.side === 'local'
							? context.localAssetBalance
							: context.remoteAssetBalance
						: output.role === 'to_remote'
						? context.side === 'local'
							? context.remoteAssetBalance
							: context.localAssetBalance
						: context.htlcs.find(
								(item) =>
									item.htlcId === output.htlcId &&
									item.direction === output.direction
						  )!.auxiliaryAmount!;
				if (!balance) continue;
				outputLeaves.set(
					output.outputIndex,
					leafFor(`${context.commitmentNumber}:${output.role}:${balance}`)
				);
				if (output.htlcId !== undefined)
					secondLevelLeaves.set(
						`${output.direction}:${output.htlcId}`,
						leafFor(`second:${context.commitmentNumber}:${balance}`)
					);
			}
			return {
				customData: Buffer.from(`view:${context.commitmentNumber}`),
				outputLeaves,
				secondLevelLeaves
			};
		},
		signHtlcs(context) {
			return new Map([[65538n, hash(context.commitment.result.tx.toBuffer())]]);
		},
		verifyHtlcs(context, records) {
			return (
				records
					.get(65538n)
					?.equals(hash(context.commitment.result.tx.toBuffer())) ?? false
			);
		},
		validateHtlc(_state, entry) {
			if (entry.customRecords?.get(65536n)?.length !== 8)
				throw new Error('Missing asset amount');
		},
		getHtlcAmount(_state, entry) {
			return entry.customRecords!.get(65536n)!.readBigUInt64BE();
		},
		prepareShutdown(state) {
			const key = state.localBasepoints.fundingPubkey;
			return {
				scriptPubkey: bitcoin.payments.p2tr({ internalPubkey: key.subarray(1) })
					.output!,
				customRecords: new Map([[65539n, key]])
			};
		},
		verifyShutdown(_state, shutdown) {
			const key = shutdown.customRecords.get(65539n);
			return (
				!!key &&
				shutdown.scriptPubkey.equals(
					bitcoin.payments.p2tr({ internalPubkey: key.subarray(1) }).output!
				)
			);
		},
		buildClose(context) {
			const auxiliary = context.state.auxiliaryState!;
			const scripts = new Map<number, Buffer>();
			for (const [index, balance, records] of [
				[
					context.localOutputIndex,
					auxiliary.localBalance,
					auxiliary.localShutdownRecords
				],
				[
					context.remoteOutputIndex,
					auxiliary.remoteBalance,
					auxiliary.remoteShutdownRecords
				]
			] as const) {
				if (index !== undefined && balance > 0n)
					scripts.set(
						index,
						bitcoin.payments.p2tr({
							internalPubkey: records!.get(65539n)!.subarray(1),
							scriptTree: { output: leafFor(`close:${balance}`).script }
						}).output!
					);
			}
			return {
				outputScripts: scripts,
				customData: Buffer.from('signed close assets')
			};
		}
	};
}

function useSeparateCloseAnchors(p: IChannelAuxiliaryProvider): void {
	p.extraCloseOutputScriptLengths = (state) =>
		[state.auxiliaryState!.localBalance, state.auxiliaryState!.remoteBalance]
			.filter((amount) => amount > 0n)
			.map(() => 34);
	p.buildClose = (context) => {
		const outputs: NonNullable<
			ReturnType<IChannelAuxiliaryProvider['buildClose']>['outputs']
		>[number][] = [];
		for (const [side, amount, balance, dust, records, script] of [
			[
				'local',
				context.localAmount,
				context.state.auxiliaryState!.localBalance,
				context.localDustLimit,
				context.state.auxiliaryState!.localShutdownRecords!,
				context.state.localShutdownScript!
			],
			[
				'remote',
				context.remoteAmount,
				context.state.auxiliaryState!.remoteBalance,
				context.remoteDustLimit,
				context.state.auxiliaryState!.remoteShutdownRecords!,
				context.state.remoteShutdownScript!
			]
		] as const) {
			if (balance > 0n) {
				const remainder = amount - 330n;
				outputs.push({
					side,
					asset: true,
					value: remainder > dust ? 330n : amount,
					script: bitcoin.payments.p2tr({
						internalPubkey: records.get(65539n)!.subarray(1),
						scriptTree: { output: leafFor(`close:${balance}`).script }
					}).output!
				});
				if (remainder > dust)
					outputs.push({ side, asset: false, value: remainder, script });
			} else if (amount > dust)
				outputs.push({ side, asset: false, value: amount, script });
		}
		outputs.sort((a, b) =>
			a.value === b.value
				? Buffer.compare(a.script, b.script)
				: a.value < b.value
				? -1
				: 1
		);
		return {
			outputs,
			outputScripts: new Map(
				outputs.map((output, index) => [index, output.script])
			),
			customData: Buffer.from('split close assets')
		};
	};
}

function config(
	seed: number,
	extension: IChannelAuxiliaryProvider,
	descriptor: IAuxiliaryFundingDescriptor
): IChannelManagerConfig {
	const keys = Array.from({ length: 5 }, (_, index) =>
		hash(`auxiliary-test:${seed}:${index}`)
	);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		localPerCommitmentSeed: hash(`commitment:${seed}`),
		localFundingPrivkey: keys[0],
		htlcBasepointSecret: keys[4],
		preferTaproot: true,
		persistence: COMMIT_ALL,
		auxiliaryChannels: {
			allowLegacyHtlcSignatures: () => true,
			provider: extension,
			resolveIncoming: (_peer, id) =>
				id.equals(descriptor.temporaryChannelId) ? descriptor : undefined
		}
	};
}

function pair(fixed = true, custody = false) {
	const descriptor = {
		temporaryChannelId: hash('auxiliary-temporary'),
		fundingTaprootMerkleRoot: hash('asset funding root'),
		channelData: Buffer.from('funding assets'),
		localBalance: 900n,
		remoteBalance: 100n
	};
	const aliceProvider = provider();
	const bobProvider = provider();
	const alice = new ChannelManager(config(1, aliceProvider, descriptor));
	const bob = new ChannelManager(
		config(2, bobProvider, {
			...descriptor,
			localBalance: 100n,
			remoteBalance: 900n
		})
	);
	const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
	const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
	if (fixed) {
		const features = FeatureFlags.empty();
		features.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
		features.setOptional(Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS);
		if (custody) features.setOptional(Feature.OPTION_ASSET_CHILD_CUSTODY);
		for (const manager of [alice, bob]) {
			manager['config'].localFeatures = features;
			manager['config'].auxiliaryChannels!.allowRevokedChildCustody = custody;
			if (custody)
				manager['config'].auxiliaryChannels!.provider.prepareRevokedChild =
					() => {
						throw new Error('Unexpected custody capsule');
					};
			manager.setFundingProvider({
				supportsFixedOutputFees: () => true,
				buildFundingTransaction: async () => {
					throw new Error('Unexpected ordinary funding');
				},
				broadcastTransaction: async () => ''
			});
			(manager as unknown as { peerManager: unknown }).peerManager = {
				getPeer: () => ({ getRemoteInit: () => ({ features }) }),
				sendToPeer: (peer: string, type: MessageType, payload: Buffer) =>
					manager.emit('message:outbound', peer, type, payload)
			};
		}
	}
	const errors: string[] = [];
	const messages: { side: string; type: number; payload: Buffer }[] = [];
	alice.on('error', (_id: unknown, error: string) =>
		errors.push(`alice:${error}`)
	);
	bob.on('error', (_id: unknown, error: string) => errors.push(`bob:${error}`));
	alice.on('message:outbound', (_peer, type, payload) => {
		messages.push({ side: 'alice', type, payload });
		bob.handleMessage(aPub, type, payload);
	});
	bob.on('message:outbound', (_peer, type, payload) => {
		messages.push({ side: 'bob', type, payload });
		alice.handleMessage(bPub, type, payload);
	});
	const aliceChannel = alice.openChannel(
		bPub,
		2_000_000n,
		500_000_000n,
		undefined,
		{ auxiliary: descriptor }
	);
	const id = alice.createFunding(
		aliceChannel,
		hash('funding transaction'),
		0,
		Buffer.alloc(64)
	)!;
	expect(id, errors.join('; ')).not.to.equal(null);
	alice.handleFundingConfirmed(id);
	bob.handleFundingConfirmed(id);
	const bobChannel = bob.getChannel(id)!;
	expect(errors, errors.join('; ')).to.deep.equal([]);
	expect(aliceChannel.getState()).to.equal(ChannelState.NORMAL);
	return {
		alice,
		bob,
		aliceChannel,
		bobChannel,
		id,
		errors,
		messages,
		bobProvider,
		aliceProvider
	};
}

function verifySpend(tx: bitcoin.Transaction, channel: Channel): void {
	const state = channel.getFullState();
	const funding = createTaprootFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey,
		undefined,
		state.fundingTaprootMerkleRoot
	);
	expect(
		ecc.verifySchnorr(
			taprootCommitmentSighash(
				tx,
				funding.p2trOutput,
				Number(state.fundingSatoshis)
			),
			funding.outputKey,
			tx.ins[0].witness[0]
		)
	).to.equal(true);
}

function nodePair() {
	const descriptor: IAuxiliaryFundingDescriptor = {
		temporaryChannelId: hash('node asset temporary'),
		fundingTaprootMerkleRoot: hash('node asset funding'),
		channelData: Buffer.from('node funding'),
		localBalance: 900n,
		remoteBalance: 100n
	};
	const stores = [new SqliteStorage(':memory:'), new SqliteStorage(':memory:')];
	stores.forEach((store) => store.open());
	const resolutions: Array<{ side: number; outcome: string; amount: bigint }> =
		[];
	const configs: IAuxiliaryChannelConfig[] = stores.map((store, side) => ({
		allowLegacyHtlcSignatures: () => true,
		provider: provider(),
		resolveIncoming: (_peer, temporaryId) =>
			temporaryId.equals(descriptor.temporaryChannelId)
				? {
						...descriptor,
						localBalance: side ? 100n : 900n,
						remoteBalance: side ? 900n : 100n
				  }
				: undefined,
		valueIncomingHtlc(context) {
			if (!context.state.auxiliaryState) return context.wireAmountMsat;
			expect(context.customRecords.get(65536n)?.readBigUInt64BE()).to.equal(
				75n
			);
			return 2_000_000n;
		},
		onHtlcResolved(context) {
			const saved = store.loadChannel(context.channelId.toString('hex'));
			expect(saved?.state.auxiliaryState?.resolvedHtlcs?.size).to.equal(1);
			expect(saved?.state.htlcs.size).to.equal(0);
			resolutions.push({
				side,
				outcome: context.outcome,
				amount: context.auxiliaryAmount
			});
		}
	}));
	const alice = createNode('auxiliary-native-payment', 1, stores[0], {
		preferTaproot: true,
		fundingProvider: {
			supportsFixedOutputFees: () => true,
			buildFundingTransaction: async () => {
				throw new Error('Unexpected ordinary Bitcoin funding');
			},
			broadcastTransaction: async () => ''
		},
		auxiliaryChannels: configs[0]
	});
	const bob = createNode('auxiliary-native-payment', 2, stores[1], {
		preferTaproot: true,
		fundingProvider: {
			supportsFixedOutputFees: () => true,
			buildFundingTransaction: async () => {
				throw new Error('Unexpected ordinary funding');
			},
			broadcastTransaction: async () => ''
		},
		auxiliaryChannels: configs[1]
	});
	const errors: string[] = [];
	alice.on('node:error', (error) => errors.push(JSON.stringify(error)));
	bob.on('node:error', (error) => errors.push(JSON.stringify(error)));
	connectNodes(alice, bob);
	const channel = alice.openAuxiliaryChannel(
		bob.getNodeId(),
		2_000_000n,
		descriptor,
		500_000_000n
	);
	const id = alice.createFunding(
		channel,
		hash('node funding transaction'),
		0,
		Buffer.alloc(64)
	)!;
	expect(id, errors.join('; ')).not.to.equal(null);
	alice.handleFundingConfirmed(id);
	bob.handleFundingConfirmed(id);
	expect(errors).to.deep.equal([]);
	return { alice, bob, id, configs, stores, resolutions, errors };
}

describe('native asset payment routing', function () {
	this.timeout(20000);
	it('settles an asset payment using quoted msat and a distinct wire carrier', function () {
		const { alice, bob, id, resolutions, errors } = nodePair();
		try {
			const invoice = bob.createInvoice({
				amountMsat: 2_000_000n,
				description: 'asset receive',
				omitAutomaticRoutingHints: true
			});
			const wires: bigint[] = [];
			alice.on('message:outbound', (_peer, type, payload) => {
				if (type === MessageType.UPDATE_ADD_HTLC)
					wires.push(decodeUpdateAddHtlcMessage(payload).amountMsat);
			});
			const route = {
				hops: [
					{
						pubkey: Buffer.from(bob.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8),
						amountToForwardMsat: 2_000_000n,
						outgoingCltvValue: 40
					}
				]
			};
			const payment = alice.sendPaymentToRoute(
				route,
				invoice.paymentHash,
				40,
				invoice.paymentSecret,
				2_000_000n,
				undefined,
				undefined,
				{
					channelId: id,
					wireAmountMsat: 600_000n,
					customRecords: amountRecord(75n)
				}
			);
			expect(errors, errors.join('; ')).to.deep.equal([]);
			expect(payment.status).to.equal(PaymentStatus.COMPLETED);
			expect(payment.amountMsat).to.equal(2_000_000n);
			expect(wires).to.deep.equal([600_000n]);
			expect(bob.getPayment(invoice.paymentHash)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(resolutions).to.have.length(2);
			expect(
				resolutions.every(
					(entry) => entry.outcome === 'fulfilled' && entry.amount === 75n
				)
			).to.equal(true);
			expect(
				bob.getChannelManager().getChannel(id)!.getFullState().auxiliaryState!
					.localBalance
			).to.equal(175n);
			expect(() =>
				alice.sendPaymentToRoute(route, hash('no asset fallback'), 40)
			).to.throw('No channel');
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});

	it('refunds a rejected asset payment and reports durable terminal failure', function () {
		const { alice, bob, id, configs, resolutions } = nodePair();
		try {
			configs[1].valueIncomingHtlc = () => {
				throw new Error('Quote expired');
			};
			const invoice = bob.createInvoice({
				amountMsat: 2_000_000n,
				description: 'expired asset quote',
				omitAutomaticRoutingHints: true
			});
			const route = {
				hops: [
					{
						pubkey: Buffer.from(bob.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8),
						amountToForwardMsat: 2_000_000n,
						outgoingCltvValue: 40
					}
				]
			};
			const payment = alice.sendPaymentToRoute(
				route,
				invoice.paymentHash,
				40,
				invoice.paymentSecret,
				2_000_000n,
				undefined,
				undefined,
				{
					channelId: id,
					wireAmountMsat: 600_000n,
					customRecords: amountRecord(75n)
				}
			);
			expect(payment.status).to.equal(PaymentStatus.FAILED);
			expect(alice.getAuxiliaryChannelInfo(id)!.localAssetBalance).to.equal(
				900n
			);
			expect(bob.getAuxiliaryChannelInfo(id)!.localAssetBalance).to.equal(100n);
			expect(resolutions).to.have.length(2);
			expect(resolutions.every((entry) => entry.outcome === 'failed')).to.equal(
				true
			);
			expect(() =>
				alice.sendPaymentToRoute(
					route,
					invoice.paymentHash,
					40,
					invoice.paymentSecret
				)
			).to.throw('explicit asset route');
			const view = alice.getAuxiliaryChannelInfo(id)!;
			view.channelData.fill(0);
			view.channelId.fill(0);
			expect(
				alice.getAuxiliaryChannelInfo(id)!.channelData.toString()
			).to.equal('node funding');
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});

	it('rejects Bitcoin-only settlement of an asset invoice and refunds the HTLC', function () {
		const { alice, bob, configs, resolutions } = nodePair();
		try {
			const ordinary = openReadyChannel(alice, bob);
			const invoice = bob.createInvoice({
				amountMsat: 2_000_000n,
				description: 'requires assets',
				omitAutomaticRoutingHints: true
			});
			configs[1].valueIncomingHtlc = (context) => {
				if (context.paymentHash.equals(invoice.paymentHash))
					throw new Error('This invoice requires assets');
				return context.wireAmountMsat;
			};
			const route = {
				hops: [
					{
						pubkey: Buffer.from(bob.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8),
						amountToForwardMsat: 2_000_000n,
						outgoingCltvValue: 40
					}
				]
			};
			const payment = alice.sendPaymentToRoute(
				route,
				invoice.paymentHash,
				40,
				invoice.paymentSecret,
				2_000_000n
			);
			expect(payment.status).to.equal(PaymentStatus.FAILED);
			expect(bob.getPayment(invoice.paymentHash)?.status).not.to.equal(
				PaymentStatus.COMPLETED
			);
			expect(
				alice.getChannelManager().getChannel(ordinary)!.getFullState().htlcs
					.size
			).to.equal(0);
			expect(resolutions).to.deep.equal([]);
		} finally {
			alice.destroy();
			bob.destroy();
		}
	});

	it('forwards an ordinary Bitcoin payment through a reserved asset quote alias', function () {
		const { alice, bob, id, configs, resolutions, errors } = nodePair();
		const payer = createNode('auxiliary-native-payment', 3);
		payer.on('node:error', (error) => errors.push(JSON.stringify(error)));
		try {
			connectNodes(payer, alice);
			const incomingChannel = openReadyChannel(payer, alice);
			const alias = Buffer.from('1122334455667788', 'hex');
			let reserved = false;
			configs[0].resolveForwardChannel = (context) =>
				context.shortChannelId.equals(alias)
					? { channelId: id, peerPubkey: bob.getNodeId() }
					: undefined;
			configs[0].prepareForwardHtlc = (context) => {
				expect(context.incomingChannelId.equals(incomingChannel)).to.equal(
					true
				);
				expect(context.amountToForwardMsat).to.equal(2_000_000n);
				expect(context.outgoingHtlcId).to.equal(context.state.localHtlcCounter);
				reserved = true;
				return {
					channelId: id,
					wireAmountMsat: 600_000n,
					customRecords: amountRecord(75n)
				};
			};
			const wires: bigint[] = [];
			alice.on('message:outbound', (peer, type, payload) => {
				if (peer === bob.getNodeId() && type === MessageType.UPDATE_ADD_HTLC) {
					expect(reserved).to.equal(true);
					wires.push(decodeUpdateAddHtlcMessage(payload).amountMsat);
				}
			});
			const invoice = bob.createInvoice({
				amountMsat: 2_000_000n,
				description: 'asset RFQ receive',
				omitAutomaticRoutingHints: true
			});
			const payment = payer.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: Buffer.from(alice.getNodeId(), 'hex'),
							shortChannelId: Buffer.alloc(8),
							amountToForwardMsat: 2_100_000n,
							outgoingCltvValue: 200
						},
						{
							pubkey: Buffer.from(bob.getNodeId(), 'hex'),
							shortChannelId: alias,
							amountToForwardMsat: 2_000_000n,
							outgoingCltvValue: 40
						}
					]
				},
				invoice.paymentHash,
				40,
				invoice.paymentSecret,
				2_000_000n
			);
			expect(errors, errors.join('; ')).to.deep.equal([]);
			expect(payment.status).to.equal(PaymentStatus.COMPLETED);
			expect(wires).to.deep.equal([600_000n]);
			expect(resolutions).to.have.length(2);
			expect(bob.getPayment(invoice.paymentHash)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			let releases = 0;
			configs[0].prepareForwardHtlc = () => ({
				channelId: id,
				wireAmountMsat: 600_000n,
				customRecords: amountRecord(9999n)
			});
			configs[0].onForwardAdmissionFailed = (context) => {
				expect(context.outgoingHtlcId).to.equal(1n);
				expect(context.state.localHtlcCounter).to.equal(1n);
				releases++;
			};
			const refusedInvoice = bob.createInvoice({
				amountMsat: 2_000_000n,
				description: 'unavailable asset liquidity',
				omitAutomaticRoutingHints: true
			});
			const refused = payer.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: Buffer.from(alice.getNodeId(), 'hex'),
							shortChannelId: Buffer.alloc(8),
							amountToForwardMsat: 2_100_000n,
							outgoingCltvValue: 200
						},
						{
							pubkey: Buffer.from(bob.getNodeId(), 'hex'),
							shortChannelId: alias,
							amountToForwardMsat: 2_000_000n,
							outgoingCltvValue: 40
						}
					]
				},
				refusedInvoice.paymentHash,
				40,
				refusedInvoice.paymentSecret,
				2_000_000n
			);
			expect(refused.status).to.equal(PaymentStatus.FAILED);
			expect(releases).to.equal(1);
			expect(wires).to.deep.equal([600_000n]);
			expect(resolutions).to.have.length(2);
		} finally {
			payer.destroy();
			alice.destroy();
			bob.destroy();
		}
	});
});

describe('native auxiliary asset channel host', function () {
	it('refuses custody downgrade and missing capsule capability without changing restored modes', () => {
		const { alice, aliceChannel, aliceProvider, bobChannel } = pair(true, true);
		const peer = bobChannel
			.getFullState()
			.localBasepoints.fundingPubkey.toString('hex');
		const type = FeatureFlags.fromBuffer(
			aliceChannel.getFullState().channelType!
		);
		type.clearBit(Feature.OPTION_ASSET_CHILD_CUSTODY);
		expect(() =>
			alice['negotiateAssetHtlcOutputs'](peer, type.toBuffer())
		).to.throw('mutually selected');
		delete aliceProvider.prepareRevokedChild;
		expect(() => alice.getAuxiliaryHtlcMode(peer)).to.throw('capsule provider');
		const restored = deserializeChannelState(
			serializeChannelState(aliceChannel.getFullState())
		);
		expect(isRevokedChildCustodyChannel(restored.channelType)).equal(true);
		const legacy = pair(true, false).aliceChannel.getFullState();
		expect(isRevokedChildCustodyChannel(legacy.channelType)).equal(false);
		expect(() =>
			acceptChildRevocationRecord(
				legacy,
				new Map([[CHILD_REVOCATION_RECORD, Buffer.alloc(66)]])
			)
		).to.throw('Unnegotiated');
	});
	for (const offeredByAlice of [true, false])
		it(`scopes explicit tower custody to a revoked ${
			offeredByAlice ? 'timeout' : 'success'
		} child and restores reordered fee variants`, () => {
			const {
				alice,
				bob,
				aliceChannel,
				bobChannel,
				aliceProvider,
				bobProvider,
				id,
				errors
			} = pair(true, true);
			expect(
				isRevokedChildCustodyChannel(aliceChannel.getFullState().channelType)
			).equal(true);
			const destination = bitcoin.payments.p2tr({
				internalPubkey: getPublicKey(hash('custody destination')).subarray(1)
			}).output!;
			aliceProvider.prepareSweep = (context) => ({
				outputScripts: new Map([[0, context.transaction.outs[0].script]]),
				customData: Buffer.from('child parent transition')
			});
			bobProvider.prepareSweep = () => ({
				outputScripts: new Map([[0, destination]]),
				customData: Buffer.from('revoked asset transition')
			});
			bobProvider.prepareRevokedChild = (context) => {
				const digest = hash('parent virtual digest');
				expect(
					ecc.verifySchnorr(
						digest,
						context.firstLevelRevocationKey.subarray(1),
						context.sign({
							transactionInputIndex: 0,
							publicKey: context.firstLevelRevocationKey,
							sigHash: digest
						})
					)
				).equal(true);
				expect(() =>
					context.sign({
						transactionInputIndex: 0,
						publicKey: context.secondLevelRevocationKey,
						sigHash: digest
					})
				).to.throw('unrelated');
				return Buffer.from('signed parent virtual packet');
			};
			const preimage = hash('scoped child HTLC');
			expect(
				(offeredByAlice ? alice : bob).addHtlc(
					id,
					100_000_000n,
					hash(preimage),
					600000,
					Buffer.alloc(1366),
					undefined,
					undefined,
					amountRecord(75n)
				).ok,
				errors.join('; ')
			).equal(true);
			expect(errors).deep.equal([]);
			const state = deserializeChannelState(
				serializeChannelState(aliceChannel.getFullState())
			);
			const restored = new Channel(
				state,
				aliceChannel.getSigner() ?? undefined,
				aliceProvider
			);
			const close = restored
				.forceClose(restored.getSigner()!)
				.find((action) => action.type === ChannelActionType.BROADCAST_TX);
			if (close?.type !== ChannelActionType.BROADCAST_TX)
				throw new Error('Missing commitment');
			const parent = bitcoin.Transaction.fromBuffer(close.tx);
			const metadata = state.auxiliaryState!.localCommitments.get(
				state.localCommitmentNumber
			)!;
			expect(metadata.secondLevelCommitmentTxid).equal(parent.getId());
			const tracked = classifyOutputs(
				parent,
				state,
				CommitmentType.OUR_COMMITMENT,
				state.localCommitmentNumber
			);
			const resolved = resolveOurCommitmentOutputs(
				state,
				tracked,
				state.localCommitmentNumber,
				destination,
				1,
				new Map([[hash(preimage).toString('hex'), preimage]]),
				hash('auxiliary-test:1:3'),
				hash('auxiliary-test:1:4'),
				state.remoteHtlcSignatures
			);
			const output = resolved.find(
				(item) =>
					item.trackedOutput.outputType ===
					(offeredByAlice ? OutputType.OFFERED_HTLC : OutputType.RECEIVED_HTLC)
			)!;
			const child = output.spendTx!;
			child.setWitness(0, output.witness!);
			expect(
				(offeredByAlice ? bob : alice).fulfillHtlc(id, 0n, preimage).ok
			).equal(true);
			expect(errors).deep.equal([]);
			const revokedState = deserializeChannelState(
				serializeChannelState(bobChannel.getFullState())
			);
			revokedState.auxiliaryProvider = bobProvider;
			const backup = buildAuxiliaryJusticePackage({
				state: revokedState,
				revokedTransaction: parent.toBuffer(),
				destinationScript: destination,
				feeRates: [1],
				revocationBasepointSecret: hash('auxiliary-test:2:1'),
				paymentBasepointSecret: hash('auxiliary-test:2:2'),
				network: bitcoin.networks.regtest
			});
			expect(backup.childCustody).length(1);
			const authority = backup.childCustody![0];
			const reorderedDescriptor = Object.fromEntries(
				Object.entries(authority).reverse()
			) as typeof authority;
			expect(
				matchAuxiliaryJusticeChild(parent, reorderedDescriptor, child, [
					parent.outs[authority.sourceOutputIndex].script
				])
			).equal(true);
			expect(
				matchAuxiliaryJusticeChild(parent, authority, child, [
					parent.outs[authority.sourceOutputIndex].script
				])
			).equal(true);
			const moved = child.clone();
			moved.addInput(hash('external fee input'), 0, 0xfffffffd);
			moved.ins.unshift(moved.ins.pop()!);
			const feeScript = bitcoin.payments.p2wpkh({
				pubkey: getPublicKey(hash('external fee key'))
			}).output!;
			const prevouts = [
				feeScript,
				parent.outs[authority.sourceOutputIndex].script
			];
			expect(
				matchAuxiliaryJusticeChild(parent, authority, moved, prevouts)
			).equal(true);
			const ownerKey = derivePrivateKey(
				hash('auxiliary-test:1:4'),
				Buffer.from(authority.perCommitmentPoint, 'hex'),
				getPublicKey(hash('auxiliary-test:1:4'))
			);
			const actualValues = [
				5000,
				parent.outs[authority.sourceOutputIndex].value
			];
			const ownerChanged = bitcoin.Transaction.fromBuffer(moved.toBuffer());
			ownerChanged.ins[1].witness[1] = Buffer.from(
				ecc.signSchnorr(
					ownerChanged.hashForWitnessV1(
						1,
						prevouts,
						actualValues,
						0,
						tapleafHash(Buffer.from(authority.htlcLeafScript, 'hex'))
					),
					ownerKey
				)
			);
			expect(
				matchAuxiliaryJusticeChild(parent, authority, ownerChanged, prevouts)
			).equal(false);
			expect(
				matchAuxiliaryJusticeChild(
					parent,
					authority,
					ownerChanged,
					prevouts,
					actualValues
				)
			).equal(true);
			expect(
				matchAuxiliaryJusticeChild(parent, authority, ownerChanged, prevouts, [
					5001,
					actualValues[1]
				])
			).equal(false);
			const peerChanged = bitcoin.Transaction.fromBuffer(moved.toBuffer());
			peerChanged.ins[1].witness[0][64] = 0x83;
			expect(
				matchAuxiliaryJusticeChild(
					parent,
					authority,
					peerChanged,
					prevouts,
					actualValues
				)
			).equal(false);
			const mutation = moved.clone();
			mutation.outs[0].value--;
			expect(
				matchAuxiliaryJusticeChild(parent, authority, mutation, prevouts)
			).equal(false);
			expect(
				matchAuxiliaryJusticeChild(parent, authority, moved, [
					destination,
					prevouts[1]
				])
			).equal(true);
			const manyInputs = bitcoin.Transaction.fromBuffer(moved.toBuffer());
			const manyScripts = [...prevouts];
			for (let index = 2; index < 66; index++) {
				manyInputs.addInput(hash(`arbitrary fee source:${index}`), 0);
				manyScripts.push(
					index % 2
						? destination
						: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE])
				);
			}
			expect(
				matchAuxiliaryJusticeChild(parent, authority, manyInputs, manyScripts)
			).equal(true);
			const remedy = buildAuxiliaryChildRemedy(
				parent,
				JSON.parse(JSON.stringify(authority)),
				moved,
				prevouts,
				(context) => {
					expect(context.capsule.toString()).equal(
						'signed parent virtual packet'
					);
					const digest = hash('child virtual digest');
					expect(
						ecc.verifySchnorr(
							digest,
							context.secondLevelRevocationKey.subarray(1),
							context.sign({
								transactionInputIndex: 0,
								publicKey: context.secondLevelRevocationKey,
								sigHash: digest
							})
						)
					).equal(true);
					return {
						outputScripts: new Map([[0, destination]]),
						customData: Buffer.from('final virtual packets')
					};
				}
			);
			// An owner may also spend its anchor from this same commitment before
			// the HTLC input. Source authentication must include the output index.
			const sameParentFee = bitcoin.Transaction.fromBuffer(moved.toBuffer());
			const anchorIndex = parent.outs.findIndex(
				(item, index) =>
					index !== authority.sourceOutputIndex && item.value === 330
			);
			expect(anchorIndex).at.least(0);
			sameParentFee.ins[0].hash = parent.getHash();
			sameParentFee.ins[0].index = anchorIndex;
			expect(
				matchAuxiliaryJusticeChild(parent, authority, sameParentFee, [
					parent.outs[anchorIndex].script,
					prevouts[1]
				])
			).equal(true);
			for (const observed of [moved, sameParentFee]) {
				const online = resolveRevokedSecondLevelOutput(
					revokedState,
					observed,
					100,
					BigInt(backup.commitmentNumber),
					destination,
					1,
					hash('auxiliary-test:2:1')
				);
				expect(online).length(1);
				const onlineTx = online[0].spendTx!;
				expect(
					ecc.verifySchnorr(
						onlineTx.hashForWitnessV1(
							0,
							[observed.outs[0].script],
							[observed.outs[0].value],
							0
						),
						observed.outs[0].script.subarray(2),
						onlineTx.ins[0].witness[0]
					)
				).equal(true);
			}
			// A provider can be temporarily unavailable after the watcher has
			// authenticated the parent spend. Neither the live attempt nor an old
			// partially persisted snapshot may suppress its second-level follow-up.
			const monitor = new ChainMonitor(
				revokedState,
				destination,
				1,
				hash('auxiliary-test:2:1'),
				hash('auxiliary-test:2:2'),
				bitcoin.networks.regtest
			);
			monitor.handleFundingSpent(parent, 90);
			const prepare = bobProvider.prepareSweep;
			bobProvider.prepareSweep = () => {
				throw new Error('Child provider interrupted');
			};
			expect(() =>
				monitor.handleOutputSpent(
					parent.getId(),
					authority.sourceOutputIndex,
					sameParentFee,
					100
				)
			).to.throw('Child provider interrupted');
			const pendingSource = monitor
				.getTrackedOutputs()
				.find((item) => item.outputIndex === authority.sourceOutputIndex)!;
			expect(pendingSource.resolutionTxid).equal(undefined);
			expect(pendingSource.status).not.equal(OutputStatus.SPEND_CONFIRMED);
			bobProvider.prepareSweep = prepare;
			for (const legacyPartialSnapshot of [false, true]) {
				const saved = deserializeChainMonitorState(
					serializeChainMonitorState(monitor.getFullState())
				);
				if (legacyPartialSnapshot) {
					const source = saved.trackedOutputs.find(
						(item) => item.outputIndex === authority.sourceOutputIndex
					)!;
					source.status = OutputStatus.SPEND_CONFIRMED;
					source.resolutionTxid = sameParentFee.getId();
					source.resolutionTxHex = sameParentFee.toHex();
					source.confirmationHeight = 100;
				}
				const resumed = ChainMonitor.restore(
					saved,
					revokedState,
					destination,
					1,
					hash('auxiliary-test:2:1'),
					hash('auxiliary-test:2:2'),
					bitcoin.networks.regtest
				);
				expect(
					resumed.handleOutputSpent(
						parent.getId(),
						authority.sourceOutputIndex,
						sameParentFee,
						100
					).length
				).greaterThan(0);
				expect(
					resumed
						.getTrackedOutputs()
						.filter(
							(item) =>
								item.txid === sameParentFee.getId() && item.outputIndex === 0
						)
				).length(1);
				expect(
					resumed.handleOutputSpent(
						parent.getId(),
						authority.sourceOutputIndex,
						sameParentFee,
						100
					)
				).deep.equal([]);
			}
			const transaction = bitcoin.Transaction.fromHex(remedy.transaction);
			expect(
				ecc.verifySchnorr(
					transaction.hashForWitnessV1(
						0,
						[moved.outs[0].script],
						[moved.outs[0].value],
						0x81
					),
					moved.outs[0].script.subarray(2),
					transaction.ins[0].witness[0].subarray(0, 64)
				)
			).equal(true);
			const variant = parent.clone();
			variant.outs[0].value--;
			expect(
				childRevocationBasepoint(
					revokedState.localPerCommitmentSeed,
					variant
				).equals(Buffer.from(authority.revocationBasepoint, 'hex'))
			).equal(false);
			const rejected = deserializeChannelState(serializeChannelState(state));
			expect(() => acceptChildRevocationRecord(rejected)).to.throw('Missing');
			const originalRecord = Buffer.concat([
				Buffer.from([1]),
				Buffer.from(parent.getId(), 'hex'),
				Buffer.from(authority.revocationBasepoint, 'hex')
			]);
			expect(() =>
				acceptChildRevocationRecord(
					rejected,
					new Map([[CHILD_REVOCATION_RECORD, originalRecord]]),
					variant
				)
			).to.throw('does not identify');
			const corrupt = Buffer.concat([
				Buffer.from([1]),
				Buffer.from(parent.getId(), 'hex'),
				getPublicKey(hash('wrong child point'))
			]);
			expect(() =>
				acceptChildRevocationRecord(
					rejected,
					new Map([[CHILD_REVOCATION_RECORD, corrupt]])
				)
			).to.throw('changed');
		});

	it('negotiates fixed peer signatures and retains the exact historical channel mode', () => {
		const { alice, bobChannel, aliceChannel } = pair();
		const state = deserializeChannelState(
			serializeChannelState(aliceChannel.getFullState())
		);
		expect(isFixedAssetHtlcChannel(state.channelType)).equal(true);
		expect(
			isFixedAssetHtlcChannel(bobChannel.getFullState().channelType)
		).equal(true);
		const peer = bobChannel
			.getFullState()
			.localBasepoints.fundingPubkey.toString('hex');
		expect(alice.getAuxiliaryHtlcMode(peer)).equal('fixed');
		retainFundingEpoch(state);
		const originalTxid = Buffer.from(state.fundingTxid!);
		state.fundingTxid = hash('later fixed-output funding');
		const compatibility = FeatureFlags.empty();
		compatibility.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
		state.channelType = compatibility.toBuffer();
		expect(
			isFixedAssetHtlcChannel(
				selectFundingEpoch(
					deserializeChannelState(serializeChannelState(state)),
					originalTxid,
					state.fundingOutputIndex
				).channelType
			)
		).equal(true);
		const legacy = pair(false).aliceChannel.getFullState();
		expect(
			isFixedAssetHtlcChannel(
				deserializeChannelState(serializeChannelState(legacy)).channelType
			)
		).equal(false);
	});

	it('refuses native downgrade, missing fee capability and implicit legacy fallback before opening', () => {
		const { alice, bobChannel } = pair();
		const peer = bobChannel
			.getFullState()
			.localBasepoints.fundingPubkey.toString('hex');
		const legacy = FeatureFlags.empty();
		legacy.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
		const internal = alice as unknown as {
			negotiateAssetHtlcOutputs(peer: string, type?: Buffer): boolean;
			peerManager: { getPeer: unknown };
		};
		expect(() =>
			internal.negotiateAssetHtlcOutputs(peer, legacy.toBuffer())
		).to.throw('downgraded');
		alice.setFundingProvider(null);
		expect(() => alice.getAuxiliaryHtlcMode(peer)).to.throw(
			'durable bounded fee preparation'
		);
		internal.peerManager.getPeer = () => ({
			getRemoteInit: () => ({ features: legacy })
		});
		alice['config'].auxiliaryChannels!.allowLegacyHtlcSignatures = () => false;
		expect(() => alice.getAuxiliaryHtlcMode(peer)).to.throw(
			'explicit peer compatibility'
		);
		alice['config'].auxiliaryChannels!.allowLegacyHtlcSignatures = (
			candidate
		) => candidate === peer;
		expect(alice.getAuxiliaryHtlcMode(peer)).equal('legacy');
	});

	it('uses peer ALL signatures that prevent a revoked owner from appending unknown asset outputs', () => {
		const { alice, aliceChannel, aliceProvider, id, errors } = pair();
		aliceProvider.prepareSweep = (context) => ({
			outputScripts: new Map([[0, context.transaction.outs[0].script]]),
			customData: Buffer.from('retained asset transition')
		});
		const preimage = hash('fixed output HTLC');
		expect(
			alice.addHtlc(
				id,
				100_000_000n,
				hash(preimage),
				600000,
				Buffer.alloc(1366),
				undefined,
				undefined,
				amountRecord(75n)
			).ok
		).equal(true);
		expect(errors).deep.equal([]);
		const state = aliceChannel.getFullState();
		const close = aliceChannel
			.forceClose(aliceChannel.getSigner()!)
			.find((action) => action.type === ChannelActionType.BROADCAST_TX);
		if (close?.type !== ChannelActionType.BROADCAST_TX)
			throw new Error('Missing commitment');
		const commitment = bitcoin.Transaction.fromBuffer(close.tx);
		const tracked = classifyOutputs(
			commitment,
			state,
			CommitmentType.OUR_COMMITMENT,
			state.localCommitmentNumber
		);
		const resolved = resolveOurCommitmentOutputs(
			state,
			tracked,
			state.localCommitmentNumber,
			bitcoin.payments.p2tr({
				internalPubkey: getPublicKey(hash('fixed destination')).subarray(1)
			}).output!,
			1,
			new Map(),
			hash('auxiliary-test:1:3'),
			hash('auxiliary-test:1:4'),
			state.remoteHtlcSignatures
		);
		const child = resolved.find(
			(item) => item.trackedOutput.outputType === OutputType.OFFERED_HTLC
		)!;
		expect(child.witness?.[0][64]).equal(0x81);
		expect(child.witness?.[1][64]).equal(0x81);
		const tx = child.spendTx!;
		tx.setWitness(0, child.witness!);
		const point = perCommitmentPointFromSecret(
			generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			)
		);
		const remoteKey = derivePublicKey(
			state.remoteBasepoints!.htlcBasepoint,
			point
		).subarray(1);
		const leafHash = tapleafHash(child.witness![child.witness!.length - 2]);
		const digest = (
			transaction: bitcoin.Transaction,
			type: number,
			inputIndex = 0
		) =>
			transaction.hashForWitnessV1(
				inputIndex,
				transaction.ins.map((_, index) =>
					index === inputIndex
						? child.trackedOutput.witnessScript!
						: Buffer.alloc(0)
				),
				transaction.ins.map((_, index) =>
					index === inputIndex ? Number(child.trackedOutput.amount) : 0
				),
				type,
				leafHash
			);
		expect(
			ecc.verifySchnorr(
				digest(tx, 0x81),
				remoteKey,
				child.witness![0].subarray(0, 64)
			)
		).equal(true);

		expect(
			verifyRemoteHtlcSignaturesTaproot(
				state,
				point,
				state.remoteHtlcSignatures,
				state.localCommitmentNumber
			)
		).equal(true);
		const wrongMode = Buffer.from(
			ecc.signSchnorr(
				digest(tx, 0x83),
				derivePrivateKey(
					hash('auxiliary-test:2:4'),
					point,
					state.remoteBasepoints!.htlcBasepoint
				)
			)
		);
		expect(
			verifyRemoteHtlcSignaturesTaproot(
				state,
				point,
				[wrongMode],
				state.localCommitmentNumber
			)
		).equal(false);
		const changed = tx.clone();
		changed.addOutput(
			bitcoin.payments.p2tr({
				internalPubkey: getPublicKey(hash('unknown exclusion key')).subarray(1)
			}).output!,
			330
		);
		const ownerKey = derivePrivateKey(
			hash('auxiliary-test:1:4'),
			point,
			state.localBasepoints.htlcBasepoint
		);
		const ownersReplacement = Buffer.from(
			ecc.signSchnorr(digest(changed, 0x83), ownerKey)
		);
		expect(
			ecc.verifySchnorr(
				digest(changed, 0x83),
				getPublicKey(ownerKey).subarray(1),
				ownersReplacement
			)
		).equal(true);
		expect(
			ecc.verifySchnorr(
				digest(changed, 0x81),
				remoteKey,
				child.witness![0].subarray(0, 64)
			)
		).equal(false);
		const reordered = tx.clone();
		reordered.addInput(hash('third party fee input'), 0);
		[reordered.ins[0], reordered.ins[1]] = [reordered.ins[1], reordered.ins[0]];
		expect(
			ecc.verifySchnorr(
				digest(reordered, 0x81, 1),
				remoteKey,
				child.witness![0].subarray(0, 64)
			)
		).equal(true);
	});
	it('uses the deployed overlay feature pair and rejects an unavailable extension', function () {
		const optional = FeatureFlags.empty();
		optional.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
		const required = FeatureFlags.empty();
		required.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
		expect(optional.listSetBits()).to.deep.equal([2025]);
		expect(required.listSetBits()).to.deep.equal([2026]);
		expect(isTaprootChannel(required.toBuffer())).to.equal(true);
		expect(isOverlayChannel(required.toBuffer())).to.equal(true);
		expect(hasUnsupportedRequiredFeatures(optional, required)).to.deep.equal(
			[]
		);
		expect(
			hasUnsupportedRequiredFeatures(FeatureFlags.empty(), required)
		).to.deep.equal([2026]);
	});

	it('negotiates the upstream auxiliary HTLC signature frame limit', function () {
		const { aliceChannel, bobChannel } = pair();
		for (const channel of [aliceChannel, bobChannel]) {
			expect(channel.getFullState().localConfig.dustLimitSatoshis).to.equal(
				354n
			);
			expect(channel.getFullState().localConfig.maxAcceptedHtlcs).to.equal(83);
			expect(channel.getFullState().remoteConfig!.maxAcceptedHtlcs).to.equal(
				83
			);
		}
		expect(DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs).to.equal(483);
	});

	it('persists asset HTLCs, settles them in both views, restores and force closes', function () {
		const { alice, bob, aliceChannel, bobChannel, id, errors, aliceProvider } =
			pair();
		const preimage = hash('settled asset payment');
		const result = alice.addHtlc(
			id,
			100_000_000n,
			hash(preimage),
			600000,
			Buffer.alloc(1366),
			undefined,
			undefined,
			amountRecord(75n)
		);
		expect(result.ok, result.error).to.equal(true);
		expect(errors).to.deep.equal([]);
		for (const channel of [aliceChannel, bobChannel]) {
			const state = channel.getFullState();
			expect([...state.htlcs.values()][0].auxiliaryAmount).to.equal(75n);
			expect(
				state.auxiliaryState!.localCommitments.get(1n)!.htlcOutputIndexes!.size
			).to.equal(1);
			expect(state.lastSentAuxiliaryRecords?.has(65538n)).to.equal(true);
		}
		expect(bob.fulfillHtlc(id, 0n, preimage).ok).to.equal(true);
		expect(errors, errors.join('; ')).to.deep.equal([]);
		expect(aliceChannel.getFullState().auxiliaryState!.localBalance).to.equal(
			825n
		);
		expect(bobChannel.getFullState().auxiliaryState!.localBalance).to.equal(
			175n
		);
		const saved = JSON.parse(
			JSON.stringify(serializeChannelState(aliceChannel.getFullState()))
		);
		const restoredState = deserializeChannelState(saved);
		expect(restoredState.auxiliaryProvider).to.equal(undefined);
		expect(
			() => new Channel(restoredState, aliceChannel.getSigner()!)
		).to.throw('provider');
		const restored = new Channel(
			restoredState,
			aliceChannel.getSigner()!,
			aliceProvider
		);
		const broadcast = restored
			.forceClose(restored.getSigner()!)
			.find((action) => action.type === ChannelActionType.BROADCAST_TX);
		expect(broadcast).not.to.equal(undefined);
		if (broadcast?.type !== ChannelActionType.BROADCAST_TX)
			throw new Error('Missing force close transaction');
		verifySpend(bitcoin.Transaction.fromBuffer(broadcast.tx), restored);
	});

	it('replays a durable asset resolution after restart until acknowledged', function () {
		const { alice, bob, aliceChannel, aliceProvider, id } = pair();
		const preimage = hash('durable resolution replay');
		alice.addHtlc(
			id,
			600_000n,
			hash(preimage),
			600000,
			Buffer.alloc(1366),
			undefined,
			undefined,
			amountRecord(75n)
		);
		bob.fulfillHtlc(id, 0n, preimage);
		const saved = serializeChannelState(aliceChannel.getFullState());
		const resolutions: string[] = [];
		const managerConfig = alice['config'];
		const restoredManager = new ChannelManager({
			...managerConfig,
			auxiliaryChannels: {
				...managerConfig.auxiliaryChannels!,
				onHtlcResolved(context) {
					resolutions.push(
						`${context.channelId.toString('hex')}:${context.direction}:${
							context.htlcId
						}:${context.outcome}`
					);
				}
			}
		});
		const restored = new Channel(
			deserializeChannelState(saved),
			aliceChannel.getSigner()!,
			aliceProvider
		);
		restoredManager.restoreChannel(restored, alice.getPeerForChannel(id)!);
		expect(resolutions).to.deep.equal([
			`${id.toString('hex')}:${HtlcDirection.OFFERED}:0:fulfilled`
		]);
		expect(
			restored.getFullState().auxiliaryState!.resolvedHtlcs!.size
		).to.equal(0);
	});

	it('rejects invalid auxiliary signatures before revoking the current state', function () {
		const { alice, bobChannel, bobProvider, id } = pair();
		bobProvider.verifyHtlcs = () => false;
		const previous = bobChannel.getFullState().localCommitmentNumber;
		alice.addHtlc(
			id,
			100_000_000n,
			hash('bad signature payment'),
			600000,
			Buffer.alloc(1366),
			undefined,
			undefined,
			amountRecord(2n)
		);
		expect(bobChannel.getFullState().localCommitmentNumber).to.equal(previous);
		expect(
			bobChannel.getFullState().auxiliaryState!.localCommitments.has(1n)
		).to.equal(false);
	});

	it('signs separate asset anchors and Bitcoin payouts with the complete close weight', function () {
		const {
			alice,
			aliceChannel,
			bobChannel,
			aliceProvider,
			bobProvider,
			id,
			errors
		} = pair();
		useSeparateCloseAnchors(aliceProvider);
		useSeparateCloseAnchors(bobProvider);
		alice.initiateShutdown(id, Buffer.from('0014' + '11'.repeat(20), 'hex'));
		expect(errors, errors.join('; ')).to.deep.equal([]);
		const state = aliceChannel.getFullState();
		const tx = bitcoin.Transaction.fromHex(state.lastCooperativeCloseTxHex!);
		expect(tx.outs.length).to.equal(4);
		expect(tx.outs.filter((output) => output.value === 330).length).to.equal(2);
		expect(tx.weight()).to.equal(960);
		expect(
			state.fundingSatoshis -
				tx.outs.reduce((sum, output) => sum + BigInt(output.value), 0n)
		).to.equal(243n);
		verifySpend(tx, aliceChannel);
		for (const channel of [aliceChannel, bobChannel])
			expect(
				deserializeChannelState(serializeChannelState(channel.getFullState()))
					.auxiliaryState!.closeTransactions!.get(tx.getId())!
					.toString()
			).to.equal('split close assets');
	});

	it('ignores only the exact accepted asset closing signature after restart', function () {
		const { alice, aliceChannel, aliceProvider, id, messages, errors } = pair();
		alice.initiateShutdown(id, Buffer.from('0014' + '11'.repeat(20), 'hex'));
		expect(errors).to.deep.equal([]);
		const wire = messages.find(
			(message) =>
				message.side === 'bob' && message.type === MessageType.CLOSING_SIGNED
		)!;
		const message = decodeClosingSignedMessage(wire.payload);
		const restored = new Channel(
			deserializeChannelState(
				JSON.parse(
					JSON.stringify(serializeChannelState(aliceChannel.getFullState()))
				)
			),
			aliceChannel.getSigner()!,
			aliceProvider
		);
		const neverSign = (): Buffer => {
			throw new Error('A closed channel must not sign again');
		};
		expect(restored.handleClosingSigned(message, neverSign)).to.deep.equal([]);
		const altered = { ...message, feeSatoshis: message.feeSatoshis + 1n };
		expect(restored.handleClosingSigned(altered, neverSign)[0].type).to.equal(
			ChannelActionType.ERROR
		);
		const invalid = { ...message, partialSignature: Buffer.alloc(32) };
		expect(restored.handleClosingSigned(invalid, neverSign)[0].type).to.equal(
			ChannelActionType.ERROR
		);
	});

	it('restores a dust-trimmed asset party and rejects a payout that loses its value', function () {
		const { aliceChannel, aliceProvider } = pair();
		useSeparateCloseAnchors(aliceProvider);
		const state = aliceChannel['_state'];
		const shutdown = aliceProvider.prepareShutdown(
			state,
			Buffer.alloc(0),
			aliceChannel['_signer']!
		);
		state.localShutdownScript = shutdown.scriptPubkey;
		state.remoteShutdownScript = shutdown.scriptPubkey;
		state.auxiliaryState!.localShutdownRecords = new Map(
			shutdown.customRecords
		);
		state.auxiliaryState!.remoteShutdownRecords = new Map(
			shutdown.customRecords
		);
		state.localBalanceMsat = 353000n;
		state.remoteBalanceMsat =
			state.fundingSatoshis * 1000n - state.localBalanceMsat;
		const tx = new bitcoin.Transaction();
		tx.addInput(Buffer.alloc(32), 0);
		applyAuxiliaryClose(state, tx, 0n);
		expect(tx.outs.map((output) => output.value)).to.include(353);
		expect(auxiliaryClosingRelayProfile(state, 0n)).to.deep.equal({
			weight: 788,
			feePaid: 0n
		});
		const build = aliceProvider.buildClose;
		aliceProvider.buildClose = (context) => {
			const result = build(context);
			const outputs = result.outputs!.map((output) => ({ ...output }));
			outputs.find((output) => output.side === 'local')!.value--;
			return { ...result, outputs };
		};
		expect(() => applyAuxiliaryClose(state, tx, 0n)).to.throw(
			'Asset close payout would lose funds'
		);
	});

	it('cooperatively closes with both rooted asset outputs and durable close payload', function () {
		const { alice, aliceChannel, bobChannel, id, errors } = pair();
		let closing: Buffer | undefined;
		alice.on('broadcast:tx', (tx) => {
			closing = tx;
		});
		alice.initiateShutdown(id, Buffer.from('0014' + '11'.repeat(20), 'hex'));
		expect(errors, errors.join('; ')).to.deep.equal([]);
		const raw =
			closing ??
			(aliceChannel.getFullState().lastCooperativeCloseTxHex
				? Buffer.from(
						aliceChannel.getFullState().lastCooperativeCloseTxHex!,
						'hex'
				  )
				: undefined);
		expect(raw).not.to.equal(undefined);
		const tx = bitcoin.Transaction.fromBuffer(raw!);
		verifySpend(tx, aliceChannel);
		expect(
			tx.outs.every((out) => out.script.length === 34 && out.script[0] === 0x51)
		).to.equal(true);
		for (const channel of [aliceChannel, bobChannel])
			expect(
				channel
					.getFullState()
					.auxiliaryState!.closeTransactions!.get(tx.getId())!
					.toString()
			).to.equal('signed close assets');
	});
});

describe('auxiliary wire and durable sweep records', function () {
	it('orders chain hashes before native asset init custom records', function () {
		const networks = [hash('regtest chain')];
		const customRecords = new Map([[65545n, Buffer.from([0, 1, 0x68])]]);
		const decoded = decodeInitMessage(
			encodeInitMessage({
				features: FeatureFlags.empty(),
				networks,
				customRecords
			})
		);
		expect(decoded.networks).to.deep.equal(networks);
		expect(decoded.customRecords).to.deep.equal(customRecords);
	});

	it('roundtrips arbitrary odd and even custom records and rejects oversized frames', function () {
		const customRecords = new Map([
			[65536n, Buffer.from('asset')],
			[65538n, Buffer.from('signature')],
			[65543n, Buffer.from('future')]
		]);
		const common = { channelId: Buffer.alloc(32), customRecords };
		const add = {
			...common,
			id: 0n,
			amountMsat: 1000n,
			paymentHash: Buffer.alloc(32),
			cltvExpiry: 500,
			onionRoutingPacket: Buffer.alloc(1366)
		};
		expect(
			decodeUpdateAddHtlcMessage(encodeUpdateAddHtlcMessage(add)).customRecords
		).to.deep.equal(customRecords);
		expect(
			decodeCommitmentSignedMessage(
				encodeCommitmentSignedMessage({
					...common,
					signature: Buffer.alloc(64),
					htlcSignatures: []
				})
			).customRecords
		).to.deep.equal(customRecords);
		expect(
			decodeShutdownMessage(
				encodeShutdownMessage({ ...common, scriptPubkey: Buffer.alloc(22) })
			).customRecords
		).to.deep.equal(customRecords);
		expect(() =>
			encodeUpdateAddHtlcMessage({
				...add,
				customRecords: new Map([[65536n, Buffer.alloc(65533)]])
			})
		).to.throw('payload');
	});

	it('preserves asset sweep proofs, HTLC identity and commitment height across storage', function () {
		const state = {
			monitorState: MonitorState.RESOLVING,
			commitmentBroadcast: null,
			currentBlockHeight: 10,
			trackedOutputs: [
				{
					txid: '00'.repeat(32),
					outputIndex: 0,
					amount: 1000n,
					outputType: OutputType.OFFERED_HTLC,
					status: OutputStatus.CONFIRMED,
					confirmationHeight: 9,
					auxiliaryData: Buffer.from('signed asset sweep'),
					auxiliaryHtlcDirection: HtlcDirection.OFFERED,
					auxiliaryCommitmentNumber: 7n,
					htlcId: 42n
				}
			]
		};
		expect(
			deserializeChainMonitorState(serializeChainMonitorState(state))
		).to.deep.equal(state);
	});
});

describe('native asset funding broadcaster configuration', () => {
	it('refuses an open before sending keys when there is no transaction broadcaster', () => {
		const node = createNode('asset-no-broadcaster', 3, undefined, {
			auxiliaryChannels: {
				provider: provider(),
				resolveIncoming: () => undefined
			}
		});
		const sent: number[] = [];
		node.on('message:outbound', (_peer, type) => sent.push(type));
		try {
			expect(() =>
				node.openAuxiliaryChannel(
					getPublicKey(hash('asset-peer')).toString('hex'),
					1_000_000n,
					{
						temporaryChannelId: hash('asset-no-broadcaster-id'),
						fundingTaprootMerkleRoot: hash('asset-root'),
						channelData: Buffer.from('funding'),
						localBalance: 100n,
						remoteBalance: 0n
					}
				)
			).to.throw('transaction broadcaster');
			expect(sent).to.deep.equal([]);
			expect(node.listChannels()).to.deep.equal([]);
		} finally {
			node.destroy();
		}
	});
});
