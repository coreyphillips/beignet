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
	isTaprootChannel
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	Feature,
	FeatureFlags,
	hasUnsupportedRequiredFeatures
} from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { taprootCommitmentSighash } from '../../src/lightning/channel/commitment-musig';
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
			provider: extension,
			resolveIncoming: (_peer, id) =>
				id.equals(descriptor.temporaryChannelId) ? descriptor : undefined
		}
	};
}

function pair() {
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
			buildFundingTransaction: async () => {
				throw new Error('Unexpected ordinary Bitcoin funding');
			},
			broadcastTransaction: async () => ''
		},
		auxiliaryChannels: configs[0]
	});
	const bob = createNode('auxiliary-native-payment', 2, stores[1], {
		preferTaproot: true,
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
