/**
 * The close of an asset channel across a restart (issue #2093): what a
 * node sent once is in its row before it leaves, and is what it sends
 * again.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ChannelState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { referenceProvider } from './helpers/auxiliary-pair';
import {
	assetHost,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

const settle = async (rounds = 80): Promise<void> => {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

const DESTINATION = Buffer.from('0014' + '11'.repeat(20), 'hex');
interface IWire {
	delivered: number;
	limit: number;
	log: Array<{ from: string; type: number; payload: Buffer }>;
}

function wire(a: IAssetHost, b: IAssetHost, ctl: IWire): void {
	const route = (from: IAssetHost, to: IAssetHost, name: string): void => {
		from.node.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== to.node.getNodeId()) return;
				ctl.log.push({ from: name, type, payload });
				if (ctl.delivered >= ctl.limit) return;
				ctl.delivered++;
				to.node.handlePeerMessage(from.node.getNodeId(), type, payload);
			}
		);
	};
	route(a, b, 'alice');
	route(b, a, 'bob');
}

async function comeBack(a: IAssetHost, b: IAssetHost): Promise<void> {
	const held: Array<() => void> = [];
	const originals = [a, b].map((host) => host.node.handlePeerMessage);
	for (const host of [a, b]) {
		const deliver = host.node.handlePeerMessage.bind(host.node);
		host.node.handlePeerMessage = ((
			peer: string,
			type: number,
			payload: Buffer
		) => {
			held.push(() => deliver(peer, type, payload));
		}) as typeof host.node.handlePeerMessage;
	}
	a.node.getChannelManager().handlePeerReconnected(b.node.getNodeId());
	b.node.getChannelManager().handlePeerReconnected(a.node.getNodeId());
	while (held.length > 0) held.shift()!();
	a.node.handlePeerMessage = originals[0];
	b.node.handlePeerMessage = originals[1];
	await settle(200);
}

describe('The close of an asset channel across a restart (#2093)', function () {
	this.timeout(240_000);
	withAssetOpens();

	/** What the row on disk holds of the shutdown exchange. */
	const rowOf = (host: IAssetHost, hex: string): string => {
		const row = host.storage!.loadChannel(hex)!.state;
		return `${row.state} script ${
			row.localShutdownScript ? 'kept' : 'absent'
		} records ${
			row.auxiliaryState!.localShutdownRecords ? 'kept' : 'absent'
		} peer-records ${
			row.auxiliaryState!.remoteShutdownRecords ? 'kept' : 'absent'
		}`;
	};
	/** Calls `probe` at the moment a shutdown of `host` leaves. */
	const atShutdownSend = (host: IAssetHost, probe: () => void): void => {
		const emit = host.node.emit.bind(host.node) as (
			event: string,
			...args: unknown[]
		) => boolean;
		(host.node as unknown as { emit: typeof emit }).emit = (
			event: string,
			...args: unknown[]
		): boolean => {
			if (event === 'message:outbound' && args[1] === MessageType.SHUTDOWN) {
				probe();
			}
			return emit(event, ...args);
		};
	};

	it('sends again the shutdown its row holds when it stopped right after its answer, though its provider would now name another key', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-close-row-'));
		const tag = 'aux-close-shutdown-window';
		const alicePath = path.join(directory, 'alice.sqlite');
		const bobPath = path.join(directory, 'bob.sqlite');
		const reference = referenceProvider();
		// A provider that closes to a key of its wallet, a new one each time
		// it is asked, as a wallet hands out addresses.
		let asked = 0;
		const walletProvider = {
			...reference,
			prepareShutdown() {
				asked++;
				const key = getPublicKey(
					crypto.createHash('sha256').update(`review9 key ${asked}`).digest()
				);
				return {
					scriptPubkey: bitcoin.payments.p2tr({
						internalPubkey: key.subarray(1)
					}).output!,
					customRecords: new Map([[65539n, key]])
				};
			}
		};
		const firstKey = getPublicKey(
			crypto.createHash('sha256').update('review9 key 1').digest()
		);
		const firstScript = bitcoin.payments.p2tr({
			internalPubkey: firstKey.subarray(1)
		}).output!;
		const open: IAssetHost[] = [];
		try {
			const alice = assetHost(tag, 1, {}, { sqlitePath: alicePath });
			let bob = assetHost(
				tag,
				2,
				{ provider: walletProvider },
				{ sqlitePath: bobPath }
			);
			open.push(alice, bob);
			const ctl: IWire = { delivered: 0, limit: Infinity, log: [] };
			wire(alice, bob, ctl);
			const channelId = await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const hex = channelId.toString('hex');
			const aliceErrors: string[] = [];
			alice.node
				.getChannelManager()
				.on('error', (_id: unknown, message: unknown) => {
					aliceErrors.push(String(message));
				});
			// Each node's row, and Bob's database as it is on disk, at the
			// moment its shutdown leaves.
			const rowAtSend = { alice: '', bob: '' };
			atShutdownSend(alice, () => {
				rowAtSend.alice = rowOf(alice, hex);
			});
			const first = bob;
			atShutdownSend(first, () => {
				rowAtSend.bob = rowOf(first, hex);
				for (const suffix of ['', '-wal', '-shm']) {
					if (fs.existsSync(bobPath + suffix)) {
						fs.copyFileSync(bobPath + suffix, `${bobPath}.snap${suffix}`);
					}
				}
			});
			ctl.delivered = 0;
			ctl.log = [];
			// Alice's shutdown and Bob's answer arrive; then Bob is gone.
			ctl.limit = 2;
			expect(alice.node.closeChannel(channelId, DESTINATION).ok).to.equal(true);
			await settle(100);
			// The row was written before the shutdown left, on the side that
			// started the close and on the side that answered.
			expect(rowAtSend.alice).to.equal(
				'SHUTTING_DOWN script kept records kept peer-records absent'
			);
			expect(rowAtSend.bob).to.equal(
				'NEGOTIATING_CLOSING script kept records kept peer-records kept'
			);
			expect(asked).to.equal(1);
			const answer = ctl.log.find(
				(m) => m.from === 'bob' && m.type === MessageType.SHUTDOWN
			)!;
			expect(answer.payload.includes(firstScript)).to.equal(true);
			expect(answer.payload.includes(firstKey)).to.equal(true);

			// Bob stops right there: his database is what it was when his
			// answer left.
			const bobId = bob.node.getNodeId();
			bob.node.destroy();
			alice.node.getChannelManager().handlePeerDisconnected(bobId);
			alice.node.removeAllListeners('message:outbound');
			for (const suffix of ['', '-wal', '-shm']) {
				if (fs.existsSync(bobPath + suffix)) fs.rmSync(bobPath + suffix);
				if (fs.existsSync(`${bobPath}.snap${suffix}`)) {
					fs.copyFileSync(`${bobPath}.snap${suffix}`, bobPath + suffix);
				}
			}
			bob = assetHost(
				tag,
				2,
				{ provider: walletProvider },
				{ sqlitePath: bobPath }
			);
			open.push(bob);
			const restored = bob.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			expect(restored.localShutdownScript).to.deep.equal(firstScript);
			expect(
				restored.auxiliaryState!.localShutdownRecords!.get(65539n)
			).to.deep.equal(firstKey);
			const after: IWire = { delivered: 0, limit: Infinity, log: [] };
			wire(alice, bob, after);
			await comeBack(alice, bob);
			await settle(200);
			// The same descriptor again, from the row: the provider, which
			// would now name another key, is not asked.
			expect(asked).to.equal(1);
			const again = after.log.filter(
				(m) => m.from === 'bob' && m.type === MessageType.SHUTDOWN
			);
			expect(again).to.have.length(1);
			expect(again[0].payload.includes(firstScript)).to.equal(true);
			expect(again[0].payload.includes(firstKey)).to.equal(true);
			expect(aliceErrors).to.deep.equal([]);
			for (const host of [alice, bob]) {
				expect(
					host.node.getChannelManager().getChannel(channelId)!.getState()
				).to.equal(ChannelState.CLOSED);
			}
		} finally {
			for (const host of open) {
				try {
					host.node.destroy();
				} catch {
					// already destroyed
				}
			}
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	it('tells the host with the close, once and across a restart, that the spend of the funding output is one it holds no asset payload for', async () => {
		const directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'aux-close-spend-')
		);
		const tag = 'aux-close-unrecorded';
		const alicePath = path.join(directory, 'alice.sqlite');
		const open: IAssetHost[] = [];
		try {
			let alice = assetHost(tag, 1, {}, { sqlitePath: alicePath });
			const bob = assetHost(tag, 2, {}, { sqlite: true });
			open.push(alice, bob);
			wire(alice, bob, { delivered: 0, limit: Infinity, log: [] });
			const channelId = await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const hex = channelId.toString('hex');
			const before = alice.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			// A spend of the funding output that is no commitment and that
			// Alice never signed.
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(
				Buffer.from(before.fundingTxid!),
				before.fundingOutputIndex!,
				0xfffffffd
			);
			tx.addOutput(
				bitcoin.payments.p2tr({
					internalPubkey: before.localBasepoints.fundingPubkey.subarray(1)
				}).output!,
				Number(before.fundingSatoshis) - 1000
			);
			tx.setWitness(0, [Buffer.alloc(64, 1)]);
			const listen = (
				host: IAssetHost
			): Array<{ channelId: Buffer; unrecordedCloseTxid?: string }> => {
				const told: Array<{
					channelId: Buffer;
					unrecordedCloseTxid?: string;
				}> = [];
				host.node.on('channel:closed', (data) => told.push(data));
				return told;
			};
			const told = listen(alice);
			alice.node.handleFundingSpent(channelId, tx, 700_000, DESTINATION);
			alice.node.handleNewBlock(700_000);
			await settle();
			// The channel ends as it does, and the host is told what it ended
			// on.
			const closed = alice.node.getChannelManager().getChannel(channelId)!;
			expect(closed.getState()).to.equal(ChannelState.CLOSED);
			expect(told).to.deep.equal([
				{ channelId, unrecordedCloseTxid: tx.getId() }
			]);
			expect(closed.getFullState().auxiliaryState!.closeTransactions).to.equal(
				undefined
			);
			expect(
				alice.storage!.loadChannel(hex)!.state.auxiliaryState!
					.unrecordedCloseTxid
			).to.equal(tx.getId());
			// The watch reports the spend again at every block: nothing more.
			alice.node.handleFundingSpent(channelId, tx, 700_000, DESTINATION);
			alice.node.handleNewBlock(700_001);
			await settle();
			expect(told).to.have.length(1);

			// After a restart the row still says so, and the same report tells
			// the host nothing a second time.
			alice.node.destroy();
			alice = assetHost(tag, 1, {}, { sqlitePath: alicePath });
			open.push(alice);
			const again = listen(alice);
			const restored = alice.node.getChannelManager().getChannel(channelId)!;
			expect(restored.getState()).to.equal(ChannelState.CLOSED);
			expect(
				restored.getFullState().auxiliaryState!.unrecordedCloseTxid
			).to.equal(tx.getId());
			alice.node.handleFundingSpent(channelId, tx, 700_000, DESTINATION);
			alice.node.handleNewBlock(700_002);
			await settle();
			expect(again).to.deep.equal([]);
			expect(
				restored.getFullState().auxiliaryState!.unrecordedCloseTxid
			).to.equal(tx.getId());
		} finally {
			for (const host of open) {
				try {
					host.node.destroy();
				} catch {
					// already destroyed
				}
			}
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	it('says nothing of the kind for the close this node signed', async () => {
		const tag = 'aux-close-recorded';
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = assetHost(tag, 2, {}, { sqlite: true });
		try {
			wire(alice, bob, { delivered: 0, limit: Infinity, log: [] });
			const channelId = await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 9000n,
				acceptorUnits: 1000n
			});
			const told: unknown[] = [];
			alice.node.on('channel:closed', (data) => told.push(data));
			const published: Buffer[] = [];
			alice.node.on('broadcast:tx', (tx: Buffer) => published.push(tx));
			expect(alice.node.closeChannel(channelId, DESTINATION).ok).to.equal(true);
			await settle();
			expect(published).to.have.length(1);
			const close = bitcoin.Transaction.fromBuffer(published[0]);
			alice.node.handleFundingSpent(channelId, close, 700_000, DESTINATION);
			alice.node.handleNewBlock(700_000);
			await settle();
			const state = alice.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState();
			expect(state.state).to.equal(ChannelState.CLOSED);
			expect(
				state.auxiliaryState!.closeTransactions!.has(close.getId())
			).to.equal(true);
			expect('unrecordedCloseTxid' in state.auxiliaryState!).to.equal(false);
			// One close, told with the channel id and nothing else.
			expect(told).to.deep.equal([{ channelId }]);
		} finally {
			alice.node.destroy();
			bob.node.destroy();
		}
	});
});
