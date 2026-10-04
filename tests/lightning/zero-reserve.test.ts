import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelAction,
	ChannelActionType
} from '../../src/lightning/channel/channel-actions';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message,
	encodeOpenChannel2Message,
	encodeAcceptChannel2Message,
	TLV_DISABLE_CHANNEL_RESERVE
} from '../../src/lightning/message/dual-funding';
import { IDualFundingParams } from '../../src/lightning/channel/dual-funding';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	makeNodeConfig,
	createNode,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';

const walletPolicy = {
	acceptWaiver: true,
	waivePeer: false,
	waiveOnOpen: false
};
const primaryPolicy = {
	acceptWaiver: false,
	waivePeer: true,
	waiveOnOpen: true
};

function pair(
	primaryOpens: boolean,
	trusted = true
): { opener: Channel; acceptor: Channel } {
	const a = makeNodeConfig('zero-reserve-open', 1);
	const b = makeNodeConfig('zero-reserve-open', 2);
	const temporaryChannelId = crypto.randomBytes(32);
	const common = {
		temporaryChannelId,
		fundingSatoshis: 1_000_000n,
		pushMsat: 100_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: a.channelBasepoints,
		localPerCommitmentSeed: a.perCommitmentSeed
	};
	const opener = new Channel(createOpenerState(common));
	const acceptor = new Channel(
		createAcceptorState({
			...common,
			localBasepoints: b.channelBasepoints,
			localPerCommitmentSeed: b.perCommitmentSeed,
			remoteBasepoints: a.channelBasepoints,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
	for (const channel of [opener, acceptor]) {
		channel.getFullState().trustedPeer = trusted;
		channel.getFullState().zeroConfEnabled = trusted;
		if (trusted) channel.getFullState().minimumDepth = 0;
	}
	opener.setZeroReservePolicy(primaryOpens ? primaryPolicy : walletPolicy);
	acceptor.setZeroReservePolicy(primaryOpens ? walletPolicy : primaryPolicy);
	return { opener, acceptor };
}

function payload(actions: ChannelAction[], type: MessageType): Buffer {
	expect(
		actions.filter((a) => a.type === ChannelActionType.ERROR)
	).to.deep.equal([]);
	const action = actions.find(
		(a) => a.type === ChannelActionType.SEND_MESSAGE && a.messageType === type
	);
	if (!action || action.type !== ChannelActionType.SEND_MESSAGE)
		throw new Error('Expected protocol message');
	return action.payload;
}

function v2Params(
	channel: Channel,
	fundingSatoshis: bigint
): IDualFundingParams {
	const s = channel.getFullState();
	return {
		fundingSatoshis,
		fundingFeeratePerkw: 253,
		commitmentFeeratePerkw: 253,
		dustLimitSatoshis: s.localConfig.dustLimitSatoshis,
		maxHtlcValueInFlightMsat: 1_000_000_000n,
		htlcMinimumMsat: 1000n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		locktime: 0,
		localBasepoints: s.localBasepoints,
		localPerCommitmentSeed: s.localPerCommitmentSeed,
		secondPerCommitmentPoint: getPublicKey(crypto.randomBytes(32)),
		channelType: Buffer.from('401000', 'hex'),
		channelFlags: 0,
		minimumDepth: 3
	};
}

describe('One-way zero reserve negotiation', () => {
	it('advertises qualified wallet support by default while preserving primary opt-in and explicit opt-out', () => {
		const cases = [
			{ config: {}, advertised: true },
			{
				config: { zeroReserve: { role: 'wallet' as const } },
				advertised: true
			},
			{ config: { zeroReserve: { advertise: false } }, advertised: false },
			{
				config: { zeroReserve: { role: 'primary' as const } },
				advertised: false
			},
			{
				config: {
					zeroReserve: { role: 'primary' as const, waiveClientReserve: true }
				},
				advertised: true
			},
			{
				config: {
					zeroReserve: {
						role: 'primary' as const,
						waiveClientReserve: true,
						advertise: false
					}
				},
				advertised: false
			}
		];
		for (const [index, item] of cases.entries()) {
			const node = createNode(
				'zero-reserve-defaults',
				index,
				undefined,
				item.config
			);
			try {
				expect(
					node.getLocalFeatures().hasFeature(Feature.OPTION_ZERO_RESERVE)
				).to.equal(item.advertised);
			} finally {
				node.destroy();
			}
		}
	});
	it('requires both advertisements and preserves the one-way role policy', () => {
		for (const role of ['wallet', 'primary'] as const) {
			for (const advertise of [false, true]) {
				for (const peerSupport of [undefined, false, true]) {
					for (const waiveClientReserve of [false, true]) {
						const localFeatures = FeatureFlags.empty();
						const remoteFeatures = FeatureFlags.empty();
						if (advertise)
							localFeatures.setOptional(Feature.OPTION_ZERO_RESERVE);
						if (peerSupport)
							remoteFeatures.setOptional(Feature.OPTION_ZERO_RESERVE);
						const manager = new ChannelManager({
							localBasepoints: makeNodeConfig('zero-reserve-policy', 1)
								.channelBasepoints!,
							localPerCommitmentSeed: makeNodeConfig('zero-reserve-policy', 1)
								.perCommitmentSeed!,
							localFundingPrivkey: makeNodeConfig('zero-reserve-policy', 1)
								.fundingPrivkey!,
							localFeatures,
							zeroReserve: { role, advertise, waiveClientReserve }
						});
						manager['peerManager'] = {
							getPeer: () => ({
								getRemoteInit: () =>
									peerSupport === undefined
										? undefined
										: { features: remoteFeatures }
							})
						} as unknown as NonNullable<(typeof manager)['peerManager']>;
						const { opener } = pair(false);
						manager['configureZeroReserve'](opener, 'peer');
						const negotiated = advertise && peerSupport === true;
						expect(opener['_zeroReservePolicy']).to.deep.equal({
							acceptWaiver: negotiated && role === 'wallet',
							waivePeer: negotiated && role === 'primary' && waiveClientReserve,
							waiveOnOpen: false
						});
						manager.setJitClients(['peer']);
						manager['configureZeroReserve'](opener, 'peer');
						expect(opener['_zeroReservePolicy'].waiveOnOpen).to.equal(true);
						manager['peerManager'] = null;
					}
				}
			}
		}
	});
	it('reserves the proposal feature and TLV constants', () => {
		expect(Feature.OPTION_ZERO_RESERVE).to.equal(64);
		expect(TLV_DISABLE_CHANNEL_RESERVE).to.equal(4n);
	});
	for (const primaryOpens of [true, false]) {
		it(`waives only the wallet reserve in v1 when ${
			primaryOpens ? 'primary' : 'wallet'
		} opens`, () => {
			const { opener, acceptor } = pair(primaryOpens);
			const open = decodeOpenChannelMessage(
				payload(opener.initiateOpen(undefined, true), MessageType.OPEN_CHANNEL)
			);
			const accept = decodeAcceptChannelMessage(
				payload(acceptor.handleOpenChannel(open), MessageType.ACCEPT_CHANNEL)
			);
			expect(opener.handleAcceptChannel(accept)).to.deep.equal([]);
			expect(open.channelReserveSatoshis).to.equal(primaryOpens ? 0n : 10_000n);
			expect(accept.channelReserveSatoshis).to.equal(
				primaryOpens ? 10_000n : 0n
			);
			const wallet = (primaryOpens ? acceptor : opener).getFullState();
			const primary = (primaryOpens ? opener : acceptor).getFullState();
			expect(wallet.localReserveWaived).to.equal(true);
			expect(wallet.remoteReserveWaived).to.equal(false);
			expect(primary.localReserveWaived).to.equal(false);
			expect(primary.remoteReserveWaived).to.equal(true);
		});
		it(`uses the directional empty v2 TLV when ${
			primaryOpens ? 'primary' : 'wallet'
		} opens`, () => {
			const { opener, acceptor } = pair(primaryOpens, false);
			opener.getFullState().announceChannel = false;
			opener.getFullState().fundingSatoshis = 800_000n;
			opener.getFullState().localBalanceMsat = 800_000_000n;
			opener.getFullState().remoteBalanceMsat = 0n;
			const open = decodeOpenChannel2Message(
				payload(
					opener.initiateOpenV2(v2Params(opener, 800_000n)),
					MessageType.OPEN_CHANNEL2
				)
			);
			acceptor.getFullState().temporaryChannelId = open.channelId;
			const accept = decodeAcceptChannel2Message(
				payload(
					acceptor.handleOpenChannel2(open, v2Params(acceptor, 200_000n)),
					MessageType.ACCEPT_CHANNEL2
				)
			);
			expect(
				opener
					.handleAcceptChannel2(accept)
					.filter((a) => a.type === ChannelActionType.ERROR)
			).to.deep.equal([]);
			expect(open.disableChannelReserve === true).to.equal(primaryOpens);
			expect(accept.disableChannelReserve === true).to.equal(!primaryOpens);
			const wallet = (primaryOpens ? acceptor : opener).getFullState();
			const primary = (primaryOpens ? opener : acceptor).getFullState();
			expect(wallet.remoteConfig.channelReserveSatoshis).to.equal(0n);
			expect(primary.remoteConfig.channelReserveSatoshis).to.equal(10_000n);
			expect(wallet.localConfig.channelReserveSatoshis).to.equal(10_000n);
			expect(primary.localConfig.channelReserveSatoshis).to.equal(0n);
			const encoded = primaryOpens
				? encodeOpenChannel2Message(open)
				: encodeAcceptChannel2Message(accept);
			expect(encoded.subarray(-2).toString('hex')).to.equal('0400');
			const malformed = Buffer.concat([
				encoded.subarray(0, -1),
				Buffer.from([1, 0])
			]);
			expect(() =>
				primaryOpens
					? decodeOpenChannel2Message(malformed)
					: decodeAcceptChannel2Message(malformed)
			).to.throw('must be empty');
		});
	}
	it('keeps both reserves on announced channels', () => {
		const { opener, acceptor } = pair(false, false);
		const open = decodeOpenChannelMessage(
			payload(opener.initiateOpen(), MessageType.OPEN_CHANNEL)
		);
		const accept = decodeAcceptChannelMessage(
			payload(acceptor.handleOpenChannel(open), MessageType.ACCEPT_CHANNEL)
		);
		expect(opener.handleAcceptChannel(accept)).to.deep.equal([]);
		expect(accept.channelReserveSatoshis).to.equal(10_000n);
		expect(acceptor.getFullState().remoteReserveWaived).to.equal(false);
	});
	it('keeps the v2 TLV absent on announced channels and on non-JIT primary opens', () => {
		for (const announced of [false, true]) {
			const { opener, acceptor } = pair(true, false);
			opener.setZeroReservePolicy({ ...primaryPolicy, waiveOnOpen: false });
			const open = decodeOpenChannel2Message(
				payload(
					opener.initiateOpenV2({
						...v2Params(opener, 1_000_000n),
						channelFlags: announced ? 1 : 0
					}),
					MessageType.OPEN_CHANNEL2
				)
			);
			acceptor.getFullState().temporaryChannelId = open.channelId;
			const accept = decodeAcceptChannel2Message(
				payload(
					acceptor.handleOpenChannel2(open, v2Params(acceptor, 0n)),
					MessageType.ACCEPT_CHANNEL2
				)
			);
			expect(open.disableChannelReserve === true).to.equal(false);
			expect(accept.disableChannelReserve === true).to.equal(false);
		}
	});
	it('refuses a v1 waiver without permission and never accepts one for a primary', () => {
		for (const policy of [
			{ acceptWaiver: false, waivePeer: false, waiveOnOpen: false },
			primaryPolicy
		]) {
			const { opener, acceptor } = pair(true);
			acceptor.setZeroReservePolicy(policy);
			const open = decodeOpenChannelMessage(
				payload(opener.initiateOpen(), MessageType.OPEN_CHANNEL)
			);
			expect(
				acceptor
					.handleOpenChannel(open)
					.some((a) => a.type === ChannelActionType.ERROR)
			).to.equal(true);
		}
	});
	it('persists both directions and treats old rows as having no waiver', () => {
		const { opener, acceptor } = pair(true);
		const open = decodeOpenChannelMessage(
			payload(opener.initiateOpen(), MessageType.OPEN_CHANNEL)
		);
		acceptor.handleOpenChannel(open);
		const row = serializeChannelState(acceptor.getFullState());
		const restored = deserializeChannelState(row);
		expect(restored.localReserveWaived).to.equal(true);
		expect(restored.remoteReserveWaived).to.equal(false);
		delete row.localReserveWaived;
		delete row.remoteReserveWaived;
		const legacy = deserializeChannelState(row);
		expect(legacy.localReserveWaived).to.equal(false);
		expect(legacy.remoteReserveWaived).to.equal(false);
	});
});

describe('Zero reserve amount and commitment checks', () => {
	function fundedPair(
		walletOpens: boolean,
		walletDust = 546n,
		primaryDust = 546n
	) {
		const primary = createNode('zero-reserve-guards', 1, undefined, {
			preferAnchors: true,
			channelConfig: {
				...DEFAULT_CHANNEL_CONFIG,
				dustLimitSatoshis: primaryDust
			}
		});
		const wallet = createNode('zero-reserve-guards', 2, undefined, {
			preferAnchors: true,
			channelConfig: {
				...DEFAULT_CHANNEL_CONFIG,
				dustLimitSatoshis: walletDust
			}
		});
		connectNodes(primary, wallet);
		const id = walletOpens
			? openReadyChannel(wallet, primary)
			: openReadyChannel(primary, wallet);
		const client = wallet.getChannelManager().getChannel(id)!;
		const server = primary.getChannelManager().getChannel(id)!;
		client.getFullState().localReserveWaived = true;
		client.getFullState().remoteConfig.channelReserveSatoshis = 0n;
		server.getFullState().remoteReserveWaived = true;
		server.getFullState().localConfig.channelReserveSatoshis = 0n;
		return { primary, wallet, client, server, id };
	}

	for (const [walletDust, primaryDust] of [
		[546n, 546n],
		[1000n, 354n],
		[354n, 1000n]
	]) {
		it(`spends the wallet opener ceiling without closing at dust ${walletDust}/${primaryDust}`, () => {
			const { primary, wallet, client, server } = fundedPair(
				true,
				walletDust,
				primaryDust
			);
			try {
				const debit = client.getSpendableOutboundMsat();
				const payment = wallet.sendPayment(
					primary.createInvoice({
						description: 'opener maximum',
						amountMsat: debit
					}).bolt11
				);
				expect(payment.status).to.equal('COMPLETED');
				expect(client.getFullState().localBalanceMsat).to.equal(1_402_000n);
				expect(client.getState()).to.equal(ChannelState.NORMAL);
				expect(server.getState()).to.equal(ChannelState.NORMAL);
			} finally {
				primary.destroy();
				wallet.destroy();
			}
		});
	}

	for (const receiving of [false, true]) {
		it(`refuses a fee update that empties the eventual high-dust commitment on ${
			receiving ? 'receive' : 'send'
		}`, () => {
			const { primary, wallet, client, server, id } = fundedPair(
				true,
				546n,
				354n
			);
			try {
				client.getFullState().localBalanceMsat = 2_071_000n;
				client.getFullState().remoteBalanceMsat = 0n;
				server.getFullState().localBalanceMsat = 0n;
				server.getFullState().remoteBalanceMsat = 2_071_000n;
				const channel = receiving ? server : client;
				const actions = receiving
					? channel.handleUpdateFee({
							channelId: id,
							feeratePerKw: 900
					  })
					: channel.updateFee(900);
				expect(
					actions.some(
						(a) =>
							a.type === ChannelActionType.ERROR &&
							/trim every output/.test(a.message)
					)
				).to.equal(true);
				expect(channel.getFullState().pendingFeeratePerKw).to.equal(undefined);
			} finally {
				primary.destroy();
				wallet.destroy();
			}
		});
	}

	it('rejects an outgoing dust HTLC that would leave the high-dust commitment empty before mutation', () => {
		const { primary, wallet, client } = fundedPair(false, 1000n, 354n);
		try {
			const s = client.getFullState();
			s.localBalanceMsat = 1_000_000n;
			s.remoteBalanceMsat = 1_400_000n;
			s.fundingSatoshis = 2400n;
			s.localConfig.channelReserveSatoshis = 354n;
			const id = s.localHtlcCounter;
			const actions = client.addHtlc(
				1000n,
				crypto.randomBytes(32),
				500,
				Buffer.alloc(1366)
			);
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.ERROR &&
						/trim every output/.test(a.message)
				)
			).to.equal(true);
			expect(s.localHtlcCounter).to.equal(id);
			expect(s.localBalanceMsat).to.equal(1_000_000n);
			expect(s.htlcs.size).to.equal(0);
		} finally {
			primary.destroy();
			wallet.destroy();
		}
	});

	it('refuses a received dust HTLC that would leave our commitment empty', () => {
		const { primary, wallet, client, id } = fundedPair(false, 1000n, 354n);
		try {
			const s = client.getFullState();
			s.localBalanceMsat = 0n;
			s.remoteBalanceMsat = 1_944_000n;
			s.fundingSatoshis = 1944n;
			s.localConfig.channelReserveSatoshis = 354n;
			const actions = client.handleUpdateAddHtlc({
				channelId: id,
				id: 0n,
				amountMsat: 1000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500,
				onionRoutingPacket: Buffer.alloc(1366)
			});
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.ERROR &&
						/trim every output/.test(a.message)
				)
			).to.equal(true);
		} finally {
			primary.destroy();
			wallet.destroy();
		}
	});

	it('refuses a fee increase the pending-splice opener balance cannot fund', () => {
		const { primary, wallet, server, id } = fundedPair(true);
		try {
			server.getFullState().localBalanceMsat = 100_000_000n;
			server.getFullState().remoteBalanceMsat = 900_000_000n;
			server.isSplicePendingLock = () => true;
			server['_splicedState'] = (view) => ({
				...view!,
				localBalanceMsat: 100_000_000n,
				remoteBalanceMsat: 944_000n,
				fundingSatoshis: 100_944n
			});
			const actions = server.handleUpdateFee({
				channelId: id,
				feeratePerKw: 900
			});
			expect(
				actions.some(
					(a) =>
						a.type === ChannelActionType.ERROR &&
						/commitment cost/.test(a.message)
				)
			).to.equal(true);
			expect(server.getFullState().pendingFeeratePerKw).to.equal(undefined);
		} finally {
			primary.destroy();
			wallet.destroy();
		}
	});

	it('prices committed dust HTLCs using the actual untrimmed output count', () => {
		const { primary, wallet, client, id } = fundedPair(true);
		try {
			wallet.sendPayment(
				primary.createInvoice({
					description: 'keep a primary output',
					amountMsat: 100_000_000n
				}).bolt11
			);
			const s = client.getFullState();
			s.localBalanceMsat -= 1000n;
			s.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 1000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500,
				onionRoutingPacket: Buffer.alloc(1366),
				state: HtlcState.COMMITTED,
				direction: HtlcDirection.OFFERED
			});
			expect(client.spliceOutCommitmentCostSats()).to.equal(944n);
			const quote = wallet.spliceQuote(id, 'out');
			expect(quote.commitmentCostSats).to.equal(944);
			expect(
				BigInt(quote.maxAmountSats + quote.feeSats + quote.commitmentCostSats!)
			).to.equal(s.localBalanceMsat / 1000n);
		} finally {
			primary.destroy();
			wallet.destroy();
		}
	});

	it('refuses a splice candidate whose peer opener cannot fund its commitment', () => {
		const { primary, wallet, server, client } = fundedPair(true);
		try {
			const candidate = {
				...server.getFullState(),
				localBalanceMsat: 100_000_000n,
				remoteBalanceMsat: 0n,
				fundingSatoshis: 100_000n
			};
			expect(server['_waivedCommitmentRefusal'](candidate)).to.include(
				'commitment cost'
			);
			expect(client.spliceOutCommitmentRefusal(1_000_000n)).to.include(
				'commitment cost'
			);
		} finally {
			primary.destroy();
			wallet.destroy();
		}
	});

	it('lets the non-opener spend every msat and keeps the opener cost', () => {
		const primary = createNode('zero-reserve-balance', 1, undefined, {
			preferAnchors: true
		});
		const wallet = createNode('zero-reserve-balance', 2, undefined, {
			preferAnchors: true
		});
		try {
			connectNodes(primary, wallet);
			const id = openReadyChannel(primary, wallet);
			primary.sendPayment(
				wallet.createInvoice({
					description: 'fund wallet',
					amountMsat: 100_000_001n
				}).bolt11
			);
			const channel = wallet.getChannelManager().getChannel(id)!;
			channel.getFullState().localReserveWaived = true;
			channel.getFullState().remoteConfig.channelReserveSatoshis = 0n;
			const peer = primary.getChannelManager().getChannel(id)!;
			peer.getFullState().remoteReserveWaived = true;
			peer.getFullState().localConfig.channelReserveSatoshis = 0n;
			expect(channel.getSpendableOutboundMsat()).to.equal(100_000_001n);
			expect(channel.spliceOutCommitmentCostSats()).to.equal(0n);
			expect(peer.spliceOutCommitmentCostSats()).to.equal(944n);
			wallet.sendPayment(
				primary.createInvoice({
					description: 'empty wallet',
					amountMsat: 100_000_001n
				}).bolt11
			);
			expect(channel.getFullState().localBalanceMsat).to.equal(0n);
			expect(channel.getState()).to.equal(ChannelState.NORMAL);
			expect(peer.getFullState().remoteConfig.channelReserveSatoshis).to.equal(
				10_000n
			);
			channel.getFullState().fundingVersion = 2;
			channel.getFullState().spliceFundingTxid = crypto.randomBytes(32);
			channel.repairKeptChannelReserve();
			expect(channel.spliceReserveWeKeepSats(5_000_000n)).to.equal(0n);
			expect(
				channel.getFullState().remoteConfig.channelReserveSatoshis
			).to.equal(0n);
		} finally {
			primary.destroy();
			wallet.destroy();
		}
	});
});
