/**
 * Issue #2093: an asset channel whose funding transaction the host
 * publishes.
 *
 * A host that funds with the unsigned form keeps the transaction to itself
 * and publishes it once the peer has signed. The node holds nothing it
 * could broadcast, so it has to find the funding the way an acceptor does:
 * from the outpoint and the script, on the chain. These tests put both
 * nodes on a chain of their own and let somebody else publish the funding.
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
import { ChannelState } from '../../src/lightning/channel/types';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { ASSET_FUNDING_ROOT } from './helpers/auxiliary-pair';
import { TestChain, TestChainBackend } from './helpers/auxiliary-chain';
import {
	assetHost,
	connectHosts,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

const sha256 = (value: string): Buffer =>
	crypto.createHash('sha256').update(value).digest();

const settle = async (): Promise<void> => {
	for (let i = 0; i < 40; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

const P2WPKH = Buffer.concat([Buffer.from('0014', 'hex'), Buffer.alloc(20, 5)]);

describe('an asset channel funded by a transaction its host publishes (issue #2093)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	const backends: TestChainBackend[] = [];
	const files: string[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			host.node.destroy();
			host.storage?.close();
		}
		for (const backend of backends.splice(0)) backend.close();
		for (const file of files.splice(0)) fs.rmSync(file, { force: true });
	});

	interface IOpening {
		chain: TestChain;
		alice: IAssetHost;
		bob: IAssetHost;
		aliceBackend: TestChainBackend;
		bobBackend: TestChainBackend;
		alicePath: string;
		told: IAuxiliaryFundingSigned[];
		channelId: Buffer;
		funding: bitcoin.Transaction;
	}

	const stateOf = (host: IAssetHost, channelId: Buffer): string =>
		host.node.getChannelManager().getChannel(channelId)?.getState() ?? 'gone';

	const errorsOf = (host: IAssetHost): string[] =>
		host.errors.filter((error) => !error.startsWith('AUTO_FUNDING_FAILED'));

	async function onChain(
		tag: string,
		seed: number,
		chain: TestChain,
		told: IAuxiliaryFundingSigned[],
		sqlitePath: string | undefined
	): Promise<{ host: IAssetHost; backend: TestChainBackend }> {
		const backend = new TestChainBackend(chain);
		backends.push(backend);
		const host = assetHost(
			tag,
			seed,
			{ onFundingSigned: (context) => void told.push(context) },
			{
				...(sqlitePath ? { sqlitePath } : { sqlite: true }),
				extra: { chainBackend: backend }
			}
		);
		hosts.push(host);
		await host.node.startChainWatcher();
		return { host, backend };
	}

	/** Alice funds with the unsigned form; Bob has signed; nothing is on chain. */
	async function opened(tag: string): Promise<IOpening> {
		const chain = new TestChain();
		const alicePath = path.join(
			os.tmpdir(),
			`${tag}-${process.pid}-${crypto.randomBytes(4).toString('hex')}.sqlite`
		);
		files.push(alicePath, `${alicePath}-wal`, `${alicePath}-shm`);
		const told: IAuxiliaryFundingSigned[] = [];
		const { host: alice, backend: aliceBackend } = await onChain(
			tag,
			1,
			chain,
			told,
			alicePath
		);
		const { host: bob, backend: bobBackend } = await onChain(
			tag,
			2,
			chain,
			[],
			undefined
		);
		connectHosts(alice, bob);
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
		const state = channel.getFullState();
		const funding = new bitcoin.Transaction();
		funding.version = 2;
		funding.addInput(sha256(`asset funding input ${tag}`), 0);
		funding.addOutput(Buffer.from('6a', 'hex'), 0);
		funding.addOutput(
			createTaprootFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints!.fundingPubkey,
				undefined,
				ASSET_FUNDING_ROOT
			).p2trOutput,
			2_000_000
		);
		const channelId = alice.node.fundAuxiliaryChannel(
			bob.node.getNodeId(),
			descriptor.temporaryChannelId,
			funding.toHex(),
			1,
			Buffer.from('final funding proofs'),
			{ prevoutScripts: [P2WPKH] }
		);
		await settle();
		expect(told).to.have.length(1);
		return {
			chain,
			alice,
			bob,
			aliceBackend,
			bobBackend,
			alicePath,
			told,
			channelId,
			funding
		};
	}

	/** Somebody else signs and publishes the funding, and blocks pass. */
	async function confirm(made: IOpening, blocks: number): Promise<void> {
		const signed = made.funding.clone();
		signed.setWitness(0, [Buffer.alloc(72, 7), Buffer.alloc(33, 2)]);
		expect(signed.getId()).to.equal(made.funding.getId());
		made.chain.seed(signed);
		await settle();
		for (let i = 0; i < blocks; i++) {
			made.chain.mine();
			await settle();
		}
	}

	const fundingHex = (made: IOpening): string[] =>
		[...made.aliceBackend.published, ...made.alice.broadcasts].filter(
			(hex) => bitcoin.Transaction.fromHex(hex).getId() === made.funding.getId()
		);

	it('reaches NORMAL when somebody else publishes the funding, and the opener publishes nothing', async () => {
		const made = await opened('aux-chain-open');
		const { alice, bob, channelId } = made;
		expect(stateOf(alice, channelId)).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(stateOf(bob, channelId)).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		// The node holds no funding transaction for the channel.
		expect(await alice.node.getFundingTxHex(channelId)).to.equal(null);

		// Blocks pass before the host publishes: nothing is sent, and the
		// channel waits.
		for (let i = 0; i < 4; i++) {
			made.chain.mine();
			await settle();
		}
		expect(made.aliceBackend.published).to.deep.equal([]);
		expect(alice.broadcasts).to.deep.equal([]);
		expect(stateOf(alice, channelId)).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		await confirm(made, 6);
		expect(stateOf(alice, channelId)).to.equal(ChannelState.NORMAL);
		expect(stateOf(bob, channelId)).to.equal(ChannelState.NORMAL);
		expect(made.aliceBackend.published).to.deep.equal([]);
		expect(made.aliceBackend.refused).to.deep.equal([]);
		expect(alice.broadcasts).to.deep.equal([]);
		expect(errorsOf(alice)).to.deep.equal([]);
		expect(errorsOf(bob)).to.deep.equal([]);
	});

	it('survives a restart between the peer signing and the confirmation', async () => {
		const made = await opened('aux-chain-restart');
		const { bob, channelId } = made;
		made.alice.node.destroy();
		made.aliceBackend.close();
		bob.node.removeAllListeners('message:outbound');
		bob.node
			.getChannelManager()
			.handlePeerDisconnected(made.alice.node.getNodeId());

		const told: IAuxiliaryFundingSigned[] = [];
		const { host: alice, backend } = await onChain(
			'aux-chain-restart',
			1,
			made.chain,
			told,
			made.alicePath
		);
		connectHosts(alice, bob);
		expect(stateOf(alice, channelId)).to.not.equal('gone');
		expect(await alice.node.getFundingTxHex(channelId)).to.equal(null);
		alice.node.getChannelManager().handlePeerReconnected(bob.node.getNodeId());
		bob.node.getChannelManager().handlePeerReconnected(alice.node.getNodeId());
		await settle();
		for (let i = 0; i < 4; i++) {
			made.chain.mine();
			await settle();
		}
		// Restarted, it still has nothing to publish and tries nothing.
		expect(backend.published).to.deep.equal([]);
		expect(alice.broadcasts).to.deep.equal([]);

		await confirm({ ...made, alice, aliceBackend: backend }, 6);
		expect(stateOf(alice, channelId)).to.equal(ChannelState.NORMAL);
		expect(stateOf(bob, channelId)).to.equal(ChannelState.NORMAL);
		expect(backend.published).to.deep.equal([]);
		expect(alice.broadcasts).to.deep.equal([]);
		// The host was told once, by the first run, and is not told again.
		expect(told).to.deep.equal([]);
		expect(errorsOf(alice)).to.deep.equal([]);
		expect(errorsOf(bob)).to.deep.equal([]);
	});

	it('a funding that never confirms is waited for and then forgotten, by the opener as by the acceptor', async () => {
		const made = await opened('aux-chain-never');
		const { alice, bob, channelId } = made;
		const txid = made.funding.getId();
		const voided: string[] = [];
		for (const [who, host] of [
			['alice', alice],
			['bob', bob]
		] as const) {
			host.node.on('channel:voided', () => void voided.push(who));
		}
		// The watcher of each node reports the funding absent, as it does
		// after three checks found nothing in the mempool or on the chain.
		const absent = async (): Promise<void> => {
			for (const host of [alice, bob]) {
				host.node.getChainWatcher()!.emit('funding:missing', channelId, txid);
			}
			await settle();
		};
		const view = (host: IAssetHost): unknown => {
			const channel = host.node.getChannelManager().getChannel(channelId);
			return channel
				? {
						state: channel.getState(),
						waiting: channel.fundingMissingSince() !== undefined,
						stored:
							host.storage!.loadChannel(channelId.toString('hex')) !== null
				  }
				: {
						state: 'gone',
						stored:
							host.storage!.loadChannel(channelId.toString('hex')) !== null
				  };
		};

		made.chain.mine();
		await settle();
		await absent();
		// Neither holds a transaction to answer with, so both start the
		// same clock and keep the channel.
		expect(view(alice)).to.deep.equal({
			state: ChannelState.AWAITING_FUNDING_CONFIRMED,
			waiting: true,
			stored: true
		});
		expect(view(bob)).to.deep.equal(view(alice));

		made.chain.advance(2015);
		await settle();
		await absent();
		expect(view(alice)).to.deep.equal({
			state: ChannelState.AWAITING_FUNDING_CONFIRMED,
			waiting: true,
			stored: true
		});
		expect(view(bob)).to.deep.equal(view(alice));
		expect(voided).to.deep.equal([]);

		made.chain.advance(2);
		await settle();
		await absent();
		expect(view(alice)).to.deep.equal({ state: 'gone', stored: false });
		expect(view(bob)).to.deep.equal(view(alice));
		expect([...voided].sort()).to.deep.equal(['alice', 'bob']);

		// At no point did the opener try to publish a funding it does not hold.
		expect(fundingHex(made)).to.deep.equal([]);
		expect(made.aliceBackend.published).to.deep.equal([]);
		expect(alice.broadcasts).to.deep.equal([]);
	});
});
