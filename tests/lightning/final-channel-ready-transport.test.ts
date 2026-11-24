import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { IChannelInfo } from '../../src/lightning/node/types';
import type { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { encodeChannelReadyMessage } from '../../src/lightning/message/channel-funding';
import {
	decodeChannelReestablishMessage,
	encodeChannelReestablishMessage
} from '../../src/lightning/message/channel-reestablish';
import { MessageType } from '../../src/lightning/message/types';
import { alice, bob, signingFixture } from './helpers/final-opening-signing';
import { FinalUpdateDataLossError } from '../../src/lightning/storage/final-channel-updates';
import type { TxidHex } from '../../src/utils/identifiers';

interface IReadyFixture {
	channelId: Buffer;
	peer: string;
	displayTxid: TxidHex;
	manager: ChannelManager;
	localReady: Buffer;
	remoteReady: Buffer;
	sent: Array<{ type: MessageType; payload: Buffer }>;
	nonce: Buffer;
	reestablish(txid?: Buffer): Buffer;
	receive(type: MessageType, bytes: Buffer, sender?: string): Promise<void>;
	peerNonce(): Buffer | undefined;
	remote(): Buffer | null;
	info(): IChannelInfo;
}

function setup(): IReadyFixture {
	const { id, candidate, terms, funding } = signingFixture(true);
	const channelId = Buffer.from(id, 'hex');
	const peer = bob.binding.nodeId;
	const signed = funding.toBuffer();
	const fundingTxid = funding.getHash();
	const displayTxid = funding.getId() as TxidHex;
	const point = bob.keys.channelBasepoints.fundingPubkey;
	const nonce = Buffer.concat([point, point]);
	const remoteReady = encodeChannelReadyMessage({
		channelId,
		secondPerCommitmentPoint: point,
		nextLocalNonce: nonce
	});
	const localReady = encodeChannelReadyMessage({
		channelId,
		secondPerCommitmentPoint: alice.keys.channelBasepoints.fundingPubkey,
		nextLocalNonce: nonce
	});
	const session = { peer, terms, channelKeyIndex: alice.index };
	let local: Buffer | null = null;
	let remote: Buffer | null = null;
	let generation = 0;
	let peerNonce: Buffer | undefined;
	let closing = false;
	const opening = (): NonNullable<
		ReturnType<SqliteStorage['loadFinalDaemonOpening']>
	> => ({
		candidate,
		session,
		funding: signed,
		...(local && remote && { readyExchanged: true }),
		...(closing && { exitToBroadcast: signed })
	});
	const store: Partial<SqliteStorage> = {
		loadFinalDaemonOpening: (key) => (key === id ? opening() : null),
		loadFinalDaemonOpenings: () => [opening()],
		loadFinalOpeningSession: (key) => (key === id ? session : null),
		loadFinalOpening: (key) => (key === id ? candidate : null),
		loadFinalSpliceAttempts: () => [],
		loadFinalLocalTxComplete: () => null,
		loadFinalPeerTxComplete: () => null,
		loadFinalOpeningExit: () => signed,
		loadFinalPeerTxSignatures: () => signed,
		loadFinalLocalTxSignatures: () => signed,
		loadFinalPeerCommitment: () => signed,
		loadFinalFundingTransaction: () => signed,
		renewFinalReestablishNonce: () =>
			Buffer.concat([
				point,
				++generation % 2 ? point : alice.keys.channelBasepoints.fundingPubkey
			]),
		rememberFinalPeerReestablishNonce: (_id, value) => {
			peerNonce = value;
		},
		finalOpeningChannelReady: () => (local = localReady),
		loadFinalLocalChannelReady: () => local,
		loadFinalPeerChannelReady: () => remote,
		rememberFinalPeerChannelReady: (_id, payload) => {
			remote = payload;
		},
		requestFinalOpeningExit: () => {
			closing = true;
			return signed;
		}
	};
	const manager = new ChannelManager({
		finalOpening: {
			storage: store as SqliteStorage,
			root: alice.root
		},
		verifyRemoteFundingInput: async () => 'unspent',
		persistence: { persist: () => 'committed' }
	} as unknown as IChannelManagerConfig);
	const sent: IReadyFixture['sent'] = [];
	manager.on('message:outbound', (_peer, type, payload) =>
		sent.push({ type, payload })
	);
	// These tests exercise refusal paths through the public dispatcher.
	manager.on('error', () => {});
	const reestablish: IReadyFixture['reestablish'] = (txid = fundingTxid) =>
		encodeChannelReestablishMessage({
			channelId,
			nextCommitmentNumber: 1n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: Buffer.from(
				terms.remoteBasepoints.firstPerCommitmentPoint,
				'hex'
			),
			nextLocalNonces: [{ fundingTxid: txid, nonce }]
		});
	const receive: IReadyFixture['receive'] = async (
		type,
		bytes,
		sender = peer
	) => {
		manager.handleMessage(sender, type, bytes);
		await new Promise<void>((done) => setImmediate(done));
	};
	return {
		channelId,
		peer,
		displayTxid,
		manager,
		localReady,
		remoteReady,
		sent,
		nonce,
		reestablish,
		receive,
		peerNonce: (): Buffer | undefined => peerNonce,
		remote: (): Buffer | null => remote,
		info: (): IChannelInfo => manager.finalOpeningInfo(channelId)[0]
	};
}

describe('Final channel readiness on the daemon dispatcher', () => {
	it('reports only the proven stale channel as errored and propagates unrelated store failures', () => {
		const f = setup();
		const store = f.manager['config'].finalOpening!.storage;
		const first = store.loadFinalDaemonOpening(f.channelId.toString('hex'))!;
		const secondId = 'ac'.repeat(32);
		store.loadFinalDaemonOpenings = (): (typeof first)[] => [
			first,
			{ ...first, candidate: { ...first.candidate, channelId: secondId } }
		];
		f.manager.finalUpdateStatus = (id): null => {
			if (id === first.candidate.channelId)
				throw new FinalUpdateDataLossError();
			return null;
		};
		const rows = f.manager.finalOpeningInfo();
		expect(rows.map((r) => r.state)).to.deep.equal([
			'ERRORED',
			'AWAITING_FUNDING_CONFIRMED'
		]);
		expect(rows[0].htlcUsable).to.equal(false);
		expect(rows[0].spendableOutboundMsat).to.equal(0n);
		expect(rows[0].localBalanceMsat).to.equal(0n);
		expect(rows[0].remoteBalanceMsat).to.equal(0n);
		f.manager.finalUpdateStatus = (): never => {
			throw new Error('Journal read failed');
		};
		expect(() => f.manager.finalOpeningInfo()).to.throw('Journal read failed');
	});

	it('treats manual final funding confirmation as a request for live verification', async () => {
		const f = setup();
		let rechecks = 0;
		const node: LightningNode = Object.assign(
			Object.create(LightningNode.prototype),
			{
				channelManager: f.manager,
				chainWatcher: {
					recheckAllWatches: (): void => {
						rechecks++;
					}
				}
			}
		);
		f.manager.handlePeerReconnected(f.peer);
		await f.receive(MessageType.CHANNEL_REESTABLISH, f.reestablish());
		node.handleFundingConfirmed(f.channelId, f.displayTxid);
		expect(rechecks).to.equal(1);
		expect(f.info().state).to.equal('AWAITING_FUNDING_CONFIRMED');
		expect(f.sent.filter((m) => m.type === MessageType.CHANNEL_READY)).to.be
			.empty;
		f.manager.handleFundingConfirmed(f.channelId, f.displayTxid);
		expect(
			f.sent.filter((m) => m.type === MessageType.CHANNEL_READY)
		).to.have.length(1);
	});
	it('orders both ready messages behind the authenticated connection and local live funding depth', async () => {
		const f = setup();
		expect(f.manager.hasChannelWithPeer(f.peer)).to.equal(true);
		expect(f.manager.countChannelsWithPeer(f.peer)).to.equal(1);
		expect(f.manager.finalOpeningPeers()).to.deep.equal([f.peer]);
		f.manager.handlePeerReconnected(f.peer);
		expect(f.sent.map((m) => m.type)).to.deep.equal([
			MessageType.CHANNEL_REESTABLISH
		]);
		await f.receive(MessageType.CHANNEL_READY, f.remoteReady);
		expect(f.remote()).to.equal(null);
		await f.receive(MessageType.CHANNEL_REESTABLISH, f.reestablish());
		expect(f.peerNonce()).to.deep.equal(f.nonce);
		await f.receive(
			MessageType.CHANNEL_READY,
			f.remoteReady,
			alice.binding.nodeId
		);
		expect(f.remote()).to.equal(null);
		await f.receive(MessageType.CHANNEL_READY, f.remoteReady);
		expect(f.remote()).to.deep.equal(f.remoteReady);
		expect(f.info().state).to.equal('AWAITING_FUNDING_CONFIRMED');
		f.manager.handleFundingConfirmed(f.channelId, '00'.repeat(32) as TxidHex);
		expect(f.sent.filter((m) => m.type === MessageType.CHANNEL_READY)).to.be
			.empty;
		f.manager.handleFundingConfirmed(f.channelId, f.displayTxid);
		expect(
			f.sent
				.filter((m) => m.type === MessageType.CHANNEL_READY)
				.map((m) => m.payload)
		).to.deep.equal([f.localReady]);
		expect(f.info()).to.include({
			state: 'CHANNEL_READY',
			spendableOutboundMsat: 0n,
			htlcUsable: false
		});
		f.manager.handleFundingConfirmed(f.channelId, f.displayTxid);
		expect(
			f.sent.filter((m) => m.type === MessageType.CHANNEL_READY)
		).to.have.length(1);
		f.manager.forgetFinalFundingConfirmation(f.channelId);
		expect(f.info().state).to.equal('AWAITING_FUNDING_CONFIRMED');
		f.manager.handleFundingConfirmed(f.channelId, f.displayTxid);
		expect(
			f.sent
				.filter((m) => m.type === MessageType.CHANNEL_READY)
				.map((m) => m.payload)
		).to.deep.equal([f.localReady, f.localReady]);
	});

	it('renews the nonce on reconnect and suppresses a ready replay during a reorg or close', async () => {
		const f = setup();
		f.manager.handleFundingConfirmed(f.channelId, f.displayTxid);
		f.manager.handlePeerReconnected(f.peer);
		await f.receive(MessageType.CHANNEL_REESTABLISH, f.reestablish());
		await f.receive(MessageType.CHANNEL_READY, f.remoteReady);
		expect(f.info().state).to.equal('CHANNEL_READY');
		f.manager.handlePeerDisconnected(f.peer);
		expect(f.info().state).to.equal('AWAITING_REESTABLISH');
		f.manager.forgetFinalFundingConfirmation(f.channelId);
		f.manager.handlePeerReconnected(f.peer);
		const reconnects = f.sent
			.filter((m) => m.type === MessageType.CHANNEL_REESTABLISH)
			.map((m) =>
				decodeChannelReestablishMessage(m.payload, { finalTaproot: true })
			);
		expect(reconnects.every((m) => m.nextFundingTxid === undefined)).to.equal(
			true
		);
		expect(reconnects[0].nextLocalNonces![0].nonce).not.to.deep.equal(
			reconnects[1].nextLocalNonces![0].nonce
		);
		await f.receive(MessageType.CHANNEL_REESTABLISH, f.reestablish());
		expect(
			f.sent.filter((m) => m.type === MessageType.CHANNEL_READY)
		).to.have.length(1);
		f.manager.forceClose(f.channelId, Buffer.alloc(1));
		f.manager.handleFundingConfirmed(f.channelId, f.displayTxid);
		expect(
			f.sent.filter((m) => m.type === MessageType.CHANNEL_READY)
		).to.have.length(1);
		expect(f.info().state).to.equal('FORCE_CLOSED');
		expect(f.manager.hasChannelWithPeer(f.peer)).to.equal(false);
		expect(f.manager.finalOpeningPeers()).to.be.empty;
	});
	it('fails the funded channel before exposing readiness when the owner sends a nonce for another funding', async () => {
		const f = setup();
		f.manager.handlePeerReconnected(f.peer);
		await f.receive(
			MessageType.CHANNEL_REESTABLISH,
			f.reestablish(Buffer.alloc(32, 42)),
			alice.binding.nodeId
		);
		expect(f.info().state).to.equal('AWAITING_FUNDING_CONFIRMED');
		await f.receive(
			MessageType.CHANNEL_REESTABLISH,
			f.reestablish(Buffer.alloc(32, 42))
		);
		expect(f.info().state).to.equal('FORCE_CLOSED');
		expect(f.peerNonce()).to.equal(undefined);
		expect(f.sent.map((m) => m.type)).to.deep.equal([
			MessageType.CHANNEL_REESTABLISH,
			MessageType.ERROR
		]);
	});
});
