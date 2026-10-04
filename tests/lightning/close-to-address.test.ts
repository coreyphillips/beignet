import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	ChannelState,
	ChannelRole,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import {
	ChannelActionType,
	IChannelPersistEvent
} from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	createNode,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';

const DESTINATION = Buffer.from(
	'512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'hex'
);
const P2WPKH = Buffer.from('0014' + '22'.repeat(20), 'hex');

describe('External cooperative close', function () {
	this.timeout(15_000);
	let alice: LightningNode;
	let bob: LightningNode;
	let storage: SqliteStorage;
	let dir: string;
	let db: string;
	let channelId: Buffer;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-close-address-'));
		db = path.join(dir, 'alice.db');
		storage = new SqliteStorage(db);
		storage.open();
		alice = createNode('close-address', 1, storage);
		bob = createNode('close-address', 2);
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);
		channelId = openReadyChannel(alice, bob);
	});
	afterEach(() => {
		alice.destroy();
		bob.destroy();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('quotes the intended script without holding or changing the channel', () => {
		const before = storage.loadChannel(channelId.toString('hex'))!.state;
		const p2wpkh = alice.closeQuote(channelId, P2WPKH);
		const p2tr = alice.closeQuote(channelId, DESTINATION);
		expect(p2tr.feeSats).to.be.greaterThan(p2wpkh.feeSats);
		expect(p2tr.amountSats + p2tr.feeSats).to.equal(1_000_000);
		expect(p2tr.feePayer).to.equal('local');
		expect(p2tr.feeEstimated).to.equal(true);
		expect(storage.loadChannel(channelId.toString('hex'))!.state).to.deep.equal(
			before
		);
		expect(
			alice.getChannelManager().getChannel(channelId)!.getState()
		).to.equal(ChannelState.NORMAL);
	});

	it('records the exact signed P2TR payout before broadcast and restores it from SQLite', () => {
		let broadcasts = 0;
		alice
			.getChannelManager()
			.prependListener('broadcast:tx', (bytes: Buffer) => {
				const tx = bitcoin.Transaction.fromBuffer(bytes);
				const saved = storage.loadChannel(channelId.toString('hex'))!.state
					.externalClose!;
				expect(saved.scriptHex).to.equal(DESTINATION.toString('hex'));
				expect(
					saved.transactions!.some(
						(entry) =>
							bitcoin.Transaction.fromHex(entry.txHex).getId() === tx.getId()
					)
				).to.equal(true);
				broadcasts++;
			});
		expect(alice.closeChannel(channelId, DESTINATION, false, true).ok).to.equal(
			true
		);
		expect(broadcasts).to.be.greaterThan(0);
		const history = alice.listExternalClosePayments();
		expect(history).to.have.length(1);
		const tx = bitcoin.Transaction.fromHex(
			alice.getChannelManager().getChannel(channelId)!.getFullState()
				.lastCooperativeCloseTxHex!
		);
		expect(history[0].amountSats).to.equal(
			tx.outs.find((out) => out.script.equals(DESTINATION))!.value
		);
		expect(history[0].amountSats + history[0].feeSats).to.equal(1_000_000);
		expect(history[0].satsPerVbyte).to.equal(
			history[0].networkFeeSats / tx.virtualSize()
		);
		alice.removeAllListeners('message:outbound');
		bob.removeAllListeners('message:outbound');
		alice.destroy();
		storage = new SqliteStorage(db);
		storage.open();
		alice = createNode('close-address', 1, storage);
		expect(alice.listExternalClosePayments()).to.deep.equal(history);
	});

	it('does not add an external send for the existing wallet close', () => {
		expect(alice.closeChannel(channelId, DESTINATION).ok).to.equal(true);
		expect(alice.listExternalClosePayments()).to.deep.equal([]);
	});

	it('withholds proposal signatures and broadcasts when candidate persistence fails', () => {
		const save = storage.saveChannel.bind(storage);
		storage.saveChannel = (id, state, peer) => {
			if (state.externalClose?.transactions?.length)
				throw new Error('candidate write failed');
			save(id, state, peer);
		};
		let signatures = 0;
		let broadcasts = 0;
		alice.on('message:outbound', (_peer: string, type: number) => {
			if (
				[
					MessageType.CLOSING_SIGNED,
					MessageType.CLOSING_COMPLETE,
					MessageType.CLOSING_SIG
				].includes(type)
			)
				signatures++;
		});
		alice.getChannelManager().on('broadcast:tx', () => broadcasts++);
		alice.closeChannel(channelId, DESTINATION, false, true);
		expect(signatures).to.equal(0);
		expect(broadcasts).to.equal(0);
		const persisted = storage.loadChannel(channelId.toString('hex'))!.state;
		expect(persisted.externalClose!.transactions).to.equal(undefined);
		expect(persisted.lastCooperativeCloseTxHex).to.equal(undefined);
		expect(alice.listExternalClosePayments()).to.deep.equal([]);
	});

	it('persists a Taproot-funded close payout across restart', () => {
		const tapDb = path.join(dir, 'taproot.db');
		let tapStorage = new SqliteStorage(tapDb);
		tapStorage.open();
		let opener = createNode('close-address-taproot', 1, tapStorage, {
			preferTaproot: true
		});
		const peer = createNode('close-address-taproot', 2, undefined, {
			preferTaproot: true
		});
		try {
			connectNodes(opener, peer);
			const id = openReadyChannel(opener, peer);
			expect(
				isTaprootChannel(
					opener.getChannelManager().getChannel(id)!.getFullState().channelType
				)
			).to.equal(true);
			expect(opener.closeChannel(id, DESTINATION, false, true).ok).to.equal(
				true
			);
			const history = opener.listExternalClosePayments();
			expect(history).to.have.length(1);
			expect(history[0].amountSats + history[0].feeSats).to.equal(1_000_000);
			opener.destroy();
			tapStorage = new SqliteStorage(tapDb);
			tapStorage.open();
			opener = createNode('close-address-taproot', 1, tapStorage, {
				preferTaproot: true
			});
			expect(opener.listExternalClosePayments()).to.deep.equal(history);
		} finally {
			opener.destroy();
			peer.destroy();
		}
	});

	it('restores a proposal-only payout when the peer published before replying', () => {
		alice.removeAllListeners('message:outbound');
		bob.removeAllListeners('message:outbound');
		const aOut: Array<{ type: number; payload: Buffer }> = [];
		const bOut: Array<{ type: number; payload: Buffer }> = [];
		alice.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) =>
				aOut.push({ type, payload })
		);
		bob.on('message:outbound', (_peer: string, type: number, payload: Buffer) =>
			bOut.push({ type, payload })
		);
		let published: bitcoin.Transaction | undefined;
		bob.getChannelManager().on('broadcast:tx', (tx: Buffer) => {
			published = bitcoin.Transaction.fromBuffer(tx);
		});
		expect(alice.closeChannel(channelId, DESTINATION, false, true).ok).to.equal(
			true
		);
		while (aOut.length) {
			const msg = aOut.shift()!;
			bob.handlePeerMessage(alice.getNodeId(), msg.type, msg.payload);
		}
		while (bOut.length) {
			const msg = bOut.shift()!;
			alice.handlePeerMessage(bob.getNodeId(), msg.type, msg.payload);
		}
		while (aOut.length) {
			const msg = aOut.shift()!;
			bob.handlePeerMessage(alice.getNodeId(), msg.type, msg.payload);
		}
		expect(published).not.to.equal(undefined);
		const before = storage.loadChannel(channelId.toString('hex'))!.state;
		expect(before.lastCooperativeCloseTxHex).to.equal(undefined);
		expect(
			before.externalClose!.transactions!.some(
				(entry) =>
					bitcoin.Transaction.fromHex(entry.txHex).getId() ===
					published!.getId()
			)
		).to.equal(true);
		alice.destroy();
		storage = new SqliteStorage(db);
		storage.open();
		alice = createNode('close-address', 1, storage);
		alice.handleFundingSpent(channelId, published!, 100, P2WPKH);
		const history = alice.listExternalClosePayments();
		expect(history).to.have.length(1);
		expect(history[0].txid).to.equal(published!.getId());
		expect(history[0].confirmationHeight).to.equal(100);
		expect(history[0].amountSats + history[0].feeSats).to.equal(1_000_000);
		alice.destroy();
		storage = new SqliteStorage(db);
		storage.open();
		alice = createNode('close-address', 1, storage);
		expect(alice.listExternalClosePayments()).to.have.length(1);
		alice.handleFundingSpent(channelId, published!, 100, P2WPKH);
		expect(alice.listExternalClosePayments()).to.deep.equal(history);
	});

	it('keeps the earlier simple-close candidate when it wins confirmation', () => {
		const flags = FeatureFlags.empty();
		flags.setOptional(Feature.SIMPLE_CLOSE);
		const aliceState = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		const bobState = bob
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		aliceState.localBalanceMsat = bobState.remoteBalanceMsat = 600_000_000n;
		aliceState.remoteBalanceMsat = bobState.localBalanceMsat = 400_000_000n;
		for (const node of [alice, bob]) {
			(
				node.getChannelManager() as unknown as { peerManager: unknown }
			).peerManager = {
				getPeer: () => ({ getRemoteInit: () => ({ features: flags }) })
			};
		}
		alice.removeAllListeners('message:outbound');
		bob.removeAllListeners('message:outbound');
		const queue: Array<() => void> = [];
		for (const [from, to] of [
			[alice, bob],
			[bob, alice]
		]) {
			from.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) =>
					queue.push(() =>
						to.handlePeerMessage(from.getNodeId(), type, payload)
					)
			);
		}
		expect(alice.closeChannel(channelId, DESTINATION, false, true).ok).to.equal(
			true
		);
		while (queue.length) queue.shift()!();
		const saved = storage.loadChannel(channelId.toString('hex'))!.state;
		const lastTxid = bitcoin.Transaction.fromHex(
			saved.lastCooperativeCloseTxHex!
		).getId();
		const earlier = saved.externalClose!.transactions!.find((entry) => {
			const tx = bitcoin.Transaction.fromHex(entry.txHex);
			return tx.getId() !== lastTxid && tx.hasWitnesses();
		});
		expect(earlier).not.to.equal(undefined);
		const tx = bitcoin.Transaction.fromHex(earlier!.txHex);
		alice.handleFundingSpent(channelId, tx, 100, P2WPKH);
		const history = alice.listExternalClosePayments();
		expect(history).to.have.length(1);
		expect(history[0].txid).to.equal(tx.getId());
		expect(history[0].amountSats + history[0].feeSats).to.equal(600_000);
		expect(history[0].feeSats).to.equal(earlier!.localFeeSats);
	});

	for (const state of [
		ChannelState.SPLICING,
		ChannelState.AWAITING_REESTABLISH
	]) {
		it(`refuses external close in ${state}`, () => {
			const channel = alice.getChannelManager().getChannel(channelId)!;
			channel.getFullState().state = state;
			expect(() => alice.closeQuote(channelId, DESTINATION)).to.throw(
				'not ready'
			);
			expect(
				alice.closeChannel(channelId, DESTINATION, false, true).ok
			).to.equal(false);
			expect(channel.getFullState().externalClose).to.equal(undefined);
		});
	}

	it('refuses unresolved HTLCs without sending shutdown or creating an intent', () => {
		const invoice = bob.createInvoice({
			description: 'pending',
			amountMsat: 10_000n,
			hold: true
		});
		alice.sendPayment(invoice.bolt11);
		let shutdowns = 0;
		alice.on('message:outbound', (_peer: string, type: number) => {
			if (type === MessageType.SHUTDOWN) shutdowns++;
		});
		expect(() => alice.closeQuote(channelId, DESTINATION)).to.throw(
			'pending HTLCs'
		);
		expect(alice.closeChannel(channelId, DESTINATION, false, true).ok).to.equal(
			false
		);
		expect(shutdowns).to.equal(0);
		expect(
			alice.getChannelManager().getChannel(channelId)!.getFullState()
				.externalClose
		).to.equal(undefined);
	});

	for (const disconnect of [false, true]) {
		it(`refuses a failed intent write and rolls back unsent state, disconnect=${disconnect}`, () => {
			const manager = alice.getChannelManager();
			manager.removeAllListeners('channel:persist');
			manager.on('channel:persist', (event: IChannelPersistEvent) => {
				event.request!.committed = false;
			});
			if (disconnect)
				manager.on('transition:blocked', () =>
					manager.handlePeerDisconnected(bob.getNodeId())
				);
			let pending = 0;
			let wire = 0;
			manager.on('channel:pending-close', () => pending++);
			alice.on('message:outbound', () => wire++);
			const result = alice.closeChannel(channelId, DESTINATION, false, true);
			expect(result.ok).to.equal(false);
			expect(result.error).to.include('not persisted');
			expect(wire).to.equal(0);
			expect(pending).to.equal(0);
			const state = alice
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			expect(state.externalClose).to.equal(undefined);
			expect(state.localShutdownScript).to.equal(null);
			expect(
				state.state === ChannelState.NORMAL ||
					state.preReestablishState === ChannelState.NORMAL
			).to.equal(true);
		});
	}

	it('allows a relayable legacy close whose remote funder output is trimmed', () => {
		const channel = alice.getChannelManager().getChannel(channelId)!;
		const state = channel.getFullState();
		state.role = ChannelRole.ACCEPTOR;
		state.localBalanceMsat = 999_800_000n;
		state.remoteBalanceMsat = 200_000n;
		state.localConfig.feeratePerKw = 500;
		state.remoteShutdownScript = P2WPKH;
		const quote = channel.quoteCooperativeClose(P2WPKH, false, 500);
		expect(quote.amountSats).to.equal(999800);
		expect(quote.feeSats).to.equal(0);
		expect(quote.networkFeeSats).to.equal(200);
	});

	it('refuses a later simple-close fee that would discard the external payout', () => {
		const channel = alice.getChannelManager().getChannel(channelId)!;
		const state = channel.getFullState();
		state.localBalanceMsat = 1_000_000n;
		state.remoteBalanceMsat = 999_000_000n;
		state.localConfig.feeratePerKw = 253;
		channel.setSimpleClose(true);
		expect(
			channel.quoteCooperativeClose(P2WPKH, true).amountSats
		).to.be.greaterThan(0);
		const actions = channel.initiateShutdown(P2WPKH, false, true);
		expect(
			actions.some((action) => action.type === ChannelActionType.ERROR)
		).to.equal(false);
		state.remoteShutdownScript = DESTINATION;
		let signatures = 0;
		const closing = channel.sendClosingComplete(800n, 0, () => {
			signatures++;
			return Buffer.alloc(64);
		});
		expect(
			closing.some((action) => action.type === ChannelActionType.ERROR)
		).to.equal(true);
		expect(signatures).to.equal(0);
	});
});
