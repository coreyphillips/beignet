/**
 * Issue #2093, step 7: the point of no return of an asset opening.
 *
 * The host funds an asset channel with a transaction of its own. Until the
 * peer has signed this node's first commitment the opening can be undone:
 * the host can abandon it, and a funding transaction given unsigned has
 * left nothing in the node to publish. The host is told at the moment the
 * peer's funding_signed is verified and written, and from then on the
 * opening is irrevocable.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import type {
	IAuxiliaryFundingDescriptor,
	IAuxiliaryFundingSigned
} from '../../src/lightning/channel/auxiliary-funding';
import { AuxiliaryOpenError } from '../../src/lightning/channel/auxiliary-guard';
import type { Channel } from '../../src/lightning/channel/channel';
import { ChannelState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { ASSET_FUNDING_ROOT } from './helpers/auxiliary-pair';
import {
	assetHost,
	connectHosts,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

const sha256 = (value: string): Buffer =>
	crypto.createHash('sha256').update(value).digest();

const settle = async (): Promise<void> => {
	for (let i = 0; i < 30; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/** A P2WPKH output script, and a P2PKH one. */
const P2WPKH = Buffer.concat([Buffer.from('0014', 'hex'), Buffer.alloc(20, 5)]);
const P2PKH = Buffer.concat([
	Buffer.from('76a914', 'hex'),
	Buffer.alloc(20, 5),
	Buffer.from('88ac', 'hex')
]);

interface ITold {
	context: IAuxiliaryFundingSigned;
	inTransaction: boolean | undefined;
	broadcasts: number;
}

describe('the point of no return of an asset opening (issue #2093, step 7)', function () {
	this.timeout(30_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
	});

	/** Alice and Bob on SQLite, with Bob's funding_signed held back on request. */
	function pair(tag: string): {
		alice: IAssetHost;
		bob: IAssetHost;
		told: ITold[];
		sent: number[];
		hold: { on: boolean };
		release: () => void;
	} {
		const told: ITold[] = [];
		const holder: { host?: IAssetHost } = {};
		const alice = assetHost(
			tag,
			1,
			{
				onFundingSigned: (context) => {
					told.push({
						context,
						inTransaction: holder.host?.storage?.inTransaction(),
						broadcasts: holder.host?.broadcasts.length ?? -1
					});
				}
			},
			{ sqlite: true }
		);
		holder.host = alice;
		const bob = assetHost(tag, 2, {}, { sqlite: true });
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const sent: number[] = [];
		alice.node.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});
		const hold = { on: false };
		const held: Array<[string, number, Buffer]> = [];
		const deliver = alice.node.handlePeerMessage.bind(alice.node);
		alice.node.handlePeerMessage = ((
			peer: string,
			type: number,
			payload: Buffer
		) => {
			if (hold.on && type === MessageType.FUNDING_SIGNED) {
				held.push([peer, type, payload]);
				return;
			}
			return deliver(peer, type, payload);
		}) as typeof alice.node.handlePeerMessage;
		return {
			alice,
			bob,
			told,
			sent,
			hold,
			release: () => {
				hold.on = false;
				for (const [peer, type, payload] of held.splice(0)) {
					deliver(peer, type, payload);
				}
			}
		};
	}

	/** Alice's opening, accepted by Bob and not yet funded. */
	async function accepted(
		alice: IAssetHost,
		bob: IAssetHost,
		tag: string
	): Promise<{ channel: Channel; descriptor: IAuxiliaryFundingDescriptor }> {
		const descriptor: IAuxiliaryFundingDescriptor = {
			temporaryChannelId: sha256(`asset channel ${tag}`),
			fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
			channelData: Buffer.from('proposed asset funding'),
			localBalance: 9000n,
			remoteBalance: 1000n
		};
		bob.incoming.set(descriptor.temporaryChannelId.toString('hex'), {
			...descriptor,
			localBalance: 1000n,
			remoteBalance: 9000n
		});
		const channel = alice.node.openAuxiliaryChannel(
			bob.node.getNodeId(),
			2_000_000n,
			descriptor,
			500_000_000n
		);
		await settle();
		expect(channel.getFullState().remoteBasepoints, 'accepted').to.not.equal(
			undefined
		);
		return { channel, descriptor };
	}

	/** The host's funding transaction for the opening, signed or not. */
	function fundingTx(
		channel: Channel,
		tag: string,
		signed: boolean
	): bitcoin.Transaction {
		const state = channel.getFullState();
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(sha256(`asset funding input ${tag}`), 0);
		if (signed) tx.setWitness(0, [Buffer.alloc(64, 7)]);
		tx.addOutput(Buffer.from('6a', 'hex'), 0);
		tx.addOutput(
			createTaprootFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints!.fundingPubkey,
				undefined,
				ASSET_FUNDING_ROOT
			).p2trOutput,
			2_000_000
		);
		return tx;
	}

	const fund = (
		alice: IAssetHost,
		bob: IAssetHost,
		descriptor: IAuxiliaryFundingDescriptor,
		tx: bitcoin.Transaction,
		prevoutScripts?: Buffer[]
	): Buffer =>
		alice.node.fundAuxiliaryChannel(
			bob.node.getNodeId(),
			descriptor.temporaryChannelId,
			tx.toHex(),
			1,
			Buffer.from('final funding proofs'),
			prevoutScripts ? { prevoutScripts } : undefined
		);

	const refusal = (run: () => unknown): AuxiliaryOpenError => {
		let error: unknown;
		try {
			run();
		} catch (err) {
			error = err;
		}
		expect(error).to.be.instanceOf(AuxiliaryOpenError);
		return error as AuxiliaryOpenError;
	};

	it('an unsigned funding leaves nothing in the node to publish, and the host is told when the peer has signed', async () => {
		const { alice, bob, told, hold, release } = pair('aux-fund-unsigned');
		const { channel, descriptor } = await accepted(alice, bob, 'unsigned');
		hold.on = true;
		const tx = fundingTx(channel, 'unsigned', false);
		const channelId = fund(alice, bob, descriptor, tx, [P2WPKH]);
		await settle();

		// funding_created is out and the peer's signature is not in: the
		// host has been told nothing, nothing was broadcast, and the opening
		// has no row.
		expect(told).to.deep.equal([]);
		expect(alice.broadcasts).to.deep.equal([]);
		expect(alice.storage!.loadChannel(channelId.toString('hex'))).to.equal(
			null
		);
		expect(channel.getState()).to.equal(ChannelState.SENT_FUNDING_CREATED);

		release();
		await settle();
		expect(told).to.have.length(1);
		expect(told[0].inTransaction).to.equal(false);
		expect(told[0].context.channelId.equals(channelId)).to.equal(true);
		expect(
			told[0].context.temporaryChannelId.equals(descriptor.temporaryChannelId)
		).to.equal(true);
		expect(told[0].context.peerPubkey).to.equal(bob.node.getNodeId());
		expect(told[0].context.fundingTxid.equals(tx.getHash())).to.equal(true);
		expect(told[0].context.fundingOutputIndex).to.equal(1);
		// The row is there, and the transaction is the host's to publish.
		expect(alice.storage!.loadChannel(channelId.toString('hex'))).to.not.equal(
			null
		);
		expect(alice.broadcasts).to.deep.equal([]);

		// From here the opening cannot be abandoned, by either id.
		for (const id of [channelId, descriptor.temporaryChannelId]) {
			const error = refusal(() => alice.node.abandonAuxiliaryOpen(id));
			expect(error.code).to.equal('ASSET_OPEN_IRREVOCABLE');
			expect(error.channelId).to.equal(id.toString('hex'));
			expect(error.message).to.include(`(channel ${id.toString('hex')})`);
		}
		expect(
			alice.node.getChannelManager().getChannel(channelId)!.getState()
		).to.not.equal(ChannelState.ERRORED);
	});

	it('a signed funding is broadcast only after the host was told', async () => {
		const { alice, bob, told, hold, release } = pair('aux-fund-signed');
		const { channel, descriptor } = await accepted(alice, bob, 'signed');
		hold.on = true;
		const tx = fundingTx(channel, 'signed', true);
		fund(alice, bob, descriptor, tx);
		await settle();
		expect(told).to.deep.equal([]);
		expect(alice.broadcasts).to.deep.equal([]);
		release();
		await settle();
		expect(told).to.have.length(1);
		expect(told[0].broadcasts).to.equal(0);
		expect(told[0].inTransaction).to.equal(false);
		expect(alice.broadcasts).to.deep.equal([tx.toHex()]);
	});

	it('an opening abandoned before it is funded is gone, and the peer is told', async () => {
		const { alice, bob, told, sent } = pair('aux-abandon-early');
		const { channel, descriptor } = await accepted(alice, bob, 'early');
		const before = sent.length;
		alice.node.abandonAuxiliaryOpen(descriptor.temporaryChannelId);
		await settle();
		expect(sent.slice(before)).to.deep.equal([MessageType.ERROR]);
		expect(
			alice.node
				.getChannelManager()
				.getTempChannel(descriptor.temporaryChannelId)
		).to.equal(undefined);
		expect(channel.getState()).to.equal(ChannelState.ERRORED);
		expect(alice.storage!.loadAllChannels()).to.deep.equal([]);
		expect(
			bob.node.getChannelManager().getTempChannel(descriptor.temporaryChannelId)
		).to.equal(undefined);
		expect(told).to.deep.equal([]);
		// Gone is gone: a second call finds no opening.
		expect(
			refusal(() =>
				alice.node.abandonAuxiliaryOpen(descriptor.temporaryChannelId)
			).code
		).to.equal('ASSET_OPEN_UNKNOWN');
	});

	for (const signed of [true, false]) {
		it(`an opening abandoned after funding_created, with a ${
			signed ? 'signed' : 'unsigned'
		} funding, leaves no row and nothing to publish, and a late funding_signed opens nothing`, async () => {
			const { alice, bob, told, sent, hold, release } = pair(
				`aux-abandon-funded-${signed}`
			);
			const { channel, descriptor } = await accepted(alice, bob, 'funded');
			hold.on = true;
			const tx = fundingTx(channel, 'funded', signed);
			const channelId = fund(
				alice,
				bob,
				descriptor,
				tx,
				signed ? undefined : [P2WPKH]
			);
			await settle();
			const before = sent.length;

			alice.node.abandonAuxiliaryOpen(channelId, 'the host cancelled');
			await settle();
			expect(sent.slice(before)).to.deep.equal([MessageType.ERROR]);
			const manager = alice.node.getChannelManager();
			expect(manager.getTempChannel(descriptor.temporaryChannelId)).to.equal(
				undefined
			);
			expect(manager.getChannel(channelId)).to.equal(undefined);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
			expect(alice.storage!.loadAllChannels()).to.deep.equal([]);

			// The peer's signature arrives after all: it opens nothing here,
			// the host is told nothing and nothing is broadcast.
			release();
			await settle();
			expect(told).to.deep.equal([]);
			expect(alice.broadcasts).to.deep.equal([]);
			expect(manager.getChannel(channelId)).to.equal(undefined);
			expect(alice.storage!.loadAllChannels()).to.deep.equal([]);
			expect(alice.node.listChannels()).to.deep.equal([]);
		});
	}

	it('a host whose callback threw is told again when the channel is restored, and no more once a call has returned and the row says so', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aux-fs-'));
		try {
			const file = path.join(directory, 'alice.sqlite');
			const calls: string[][] = [[], [], []];
			const start = (run: number, fail: boolean): IAssetHost =>
				assetHost(
					'aux-fs-again',
					1,
					{
						onFundingSigned: (context) => {
							calls[run].push(context.channelId.toString('hex'));
							if (fail) throw new Error('host store is down');
						}
					},
					{ sqlitePath: file }
				);
			const stop = (host: IAssetHost): void => {
				host.node.destroy();
				host.storage!.close();
			};
			const first = start(0, true);
			const bob = assetHost('aux-fs-again', 2, {}, { sqlite: true });
			hosts.push(bob);
			connectHosts(first, bob);
			const { channel, descriptor } = await accepted(first, bob, 'again');
			const channelId = fund(
				first,
				bob,
				descriptor,
				fundingTx(channel, 'again', false),
				[P2WPKH]
			);
			const hex = channelId.toString('hex');
			await settle();
			// The peer signed, the row is written, the host was called and
			// threw: irrevocable, and not marked as told.
			expect(calls[0]).to.deep.equal([hex]);
			expect(first.storage!.loadChannel(hex)).to.not.equal(null);
			expect(first.errors.join('\n')).to.include(
				`Asset funding callback failed (channel ${hex}): host store is down`
			);
			expect(
				refusal(() => first.node.abandonAuxiliaryOpen(channelId)).code
			).to.equal('ASSET_OPEN_IRREVOCABLE');
			expect(
				channel.getFullState().auxiliaryState!.fundingSignedDelivered
			).to.equal(undefined);
			stop(first);

			// Restored from its row: told again, and this call returns.
			const second = start(1, false);
			await settle();
			expect(calls[1]).to.deep.equal([hex]);
			expect(
				refusal(() => second.node.abandonAuxiliaryOpen(channelId)).code
			).to.equal('ASSET_OPEN_IRREVOCABLE');
			// The mark rides the next write of the row.
			second.node.handleFundingConfirmed(channelId);
			await settle();
			expect(calls[1]).to.deep.equal([hex]);
			stop(second);

			const third = start(2, false);
			hosts.push(third);
			await settle();
			expect(calls[2]).to.deep.equal([]);
			expect(
				third.node.getChannelManager().getChannel(channelId)!.getFullState()
					.auxiliaryState!.fundingSignedDelivered
			).to.equal(true);
		} finally {
			for (const host of hosts.splice(0)) {
				host.node.destroy();
				host.storage?.close();
			}
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	describe('a funding_signed whose row could not be written', () => {
		/** Alice's storage refuses the write that funding_signed asks for. */
		async function unwritten(tag: string): Promise<{
			alice: IAssetHost;
			bob: IAssetHost;
			told: ITold[];
			sent: number[];
			channelId: Buffer;
			refused: () => number;
		}> {
			const { alice, bob, told, sent } = pair(tag);
			const { channel, descriptor } = await accepted(alice, bob, tag);
			const persistence = (
				alice.node.getChannelManager() as unknown as {
					persistence: { persist: (...args: unknown[]) => unknown };
				}
			).persistence;
			const persist = persistence.persist.bind(persistence);
			const failing = { on: false, refused: 0 };
			persistence.persist = (...args: unknown[]): unknown => {
				if (failing.on) {
					failing.refused++;
					return { committed: false, outboxIds: [] };
				}
				return persist(...args);
			};
			const deliver = alice.node.handlePeerMessage.bind(alice.node);
			alice.node.handlePeerMessage = ((
				peer: string,
				type: number,
				payload: Buffer
			) => {
				if (type === MessageType.FUNDING_SIGNED) failing.on = true;
				try {
					return deliver(peer, type, payload);
				} finally {
					if (type === MessageType.FUNDING_SIGNED) failing.on = false;
				}
			}) as typeof alice.node.handlePeerMessage;
			const channelId = fund(
				alice,
				bob,
				descriptor,
				fundingTx(channel, tag, false),
				[P2WPKH]
			);
			await settle();
			// Verified in memory, refused by the disk: no row, nothing told.
			expect(failing.refused).to.be.at.least(1);
			expect(channel.getState()).to.not.equal(
				ChannelState.SENT_FUNDING_CREATED
			);
			expect(alice.storage!.loadChannel(channelId.toString('hex'))).to.equal(
				null
			);
			expect(told).to.deep.equal([]);
			return {
				alice,
				bob,
				told,
				sent,
				channelId,
				refused: () => failing.refused
			};
		}

		it('can still be abandoned: the row decides, not memory', async () => {
			const { alice, told, sent, channelId } = await unwritten('aux-fs-norow');
			const before = sent.length;
			alice.node.abandonAuxiliaryOpen(channelId, 'the host cancelled');
			await settle();
			expect(sent.slice(before)).to.deep.equal([MessageType.ERROR]);
			expect(alice.node.getChannelManager().getChannel(channelId)).to.equal(
				undefined
			);
			expect(alice.storage!.loadAllChannels()).to.deep.equal([]);
			expect(told).to.deep.equal([]);
			expect(alice.broadcasts).to.deep.equal([]);
			expect(
				refusal(() => alice.node.abandonAuxiliaryOpen(channelId)).code
			).to.equal('ASSET_OPEN_UNKNOWN');
		});

		it('tells the host once, after the next write of the channel that commits, and is irrevocable from then on', async () => {
			const { alice, told, channelId } = await unwritten('aux-fs-later');
			alice.node.handleFundingConfirmed(channelId);
			await settle();
			expect(
				alice.storage!.loadChannel(channelId.toString('hex'))
			).to.not.equal(null);
			expect(told).to.have.length(1);
			expect(told[0].inTransaction).to.equal(false);
			expect(told[0].context.channelId.equals(channelId)).to.equal(true);
			expect(
				refusal(() => alice.node.abandonAuxiliaryOpen(channelId)).code
			).to.equal('ASSET_OPEN_IRREVOCABLE');
			// Told once: further writes deliver nothing more.
			alice.node
				.getChannelManager()
				.handlePeerDisconnected(told[0].context.peerPubkey);
			await settle();
			expect(told).to.have.length(1);
		});
	});

	it('an id that is not an asset opening of this node is refused by name', async () => {
		const { alice, bob } = pair('aux-abandon-unknown');
		const unknown = sha256('no such opening');
		const error = refusal(() => alice.node.abandonAuxiliaryOpen(unknown));
		expect(error.code).to.equal('ASSET_OPEN_UNKNOWN');
		expect(error.message).to.include(`(channel ${unknown.toString('hex')})`);
		// The acceptor of an opening cannot abandon it for its opener.
		const { descriptor } = await accepted(alice, bob, 'acceptor');
		expect(
			refusal(() =>
				bob.node.abandonAuxiliaryOpen(descriptor.temporaryChannelId)
			).code
		).to.equal('ASSET_OPEN_UNKNOWN');
	});

	it('refuses an unsigned funding whose id could still change', async () => {
		const { alice, bob } = pair('aux-fund-refused');
		const { channel, descriptor } = await accepted(alice, bob, 'refused');
		const id = descriptor.temporaryChannelId.toString('hex');
		const unsigned = fundingTx(channel, 'refused', false);
		const signed = fundingTx(channel, 'refused', true);
		const nested = fundingTx(channel, 'refused', false);
		nested.ins[0].script = Buffer.concat([Buffer.from([22]), P2WPKH]);
		const p2sh = (program: Buffer): Buffer =>
			Buffer.concat([
				Buffer.from('a914', 'hex'),
				bitcoin.crypto.hash160(program),
				Buffer.from('87', 'hex')
			]);
		const cases: Array<[bitcoin.Transaction, Buffer[], string]> = [
			[
				unsigned,
				[P2PKH],
				`Asset funding transaction has an input that is not segwit (channel ${id})`
			],
			[
				unsigned,
				[],
				`Asset funding transaction needs the script each of its inputs spends (channel ${id})`
			],
			[
				signed,
				[P2WPKH],
				`Asset funding transaction given with the scripts it spends has to be unsigned (channel ${id})`
			],
			[
				// A scriptSig that is not the program its output commits to.
				nested,
				[
					p2sh(Buffer.concat([Buffer.from('0014', 'hex'), Buffer.alloc(20, 6)]))
				],
				`Asset funding transaction has an input that is not segwit (channel ${id})`
			]
		];
		for (const [tx, scripts, message] of cases) {
			expect(() => fund(alice, bob, descriptor, tx, scripts)).to.throw(message);
		}
		expect(channel.getState()).to.equal(ChannelState.SENT_ACCEPT);
		// Nested in P2SH with the program already in place, it is taken.
		const channelId = fund(alice, bob, descriptor, nested, [p2sh(P2WPKH)]);
		await settle();
		expect(
			alice.node.getChannelManager().getChannel(channelId)?.getState()
		).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
	});
});
