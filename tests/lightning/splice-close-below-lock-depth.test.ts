/**
 * Issue #764: a splice that is on chain but below its lock depth.
 *
 * From the moment the splice is mined the pre-splice funding output is spent,
 * so every commitment built against it is unconfirmable; the lock, and with it
 * the adoption, waits for `lockAtDepth`. A force close in that window must be
 * built against the splice, WITHOUT moving the channel onto it: the splice can
 * still be reorged out, and only an unmoved channel can still build the
 * pre-splice commitment the close would then have to go back to.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChainWatcher,
	IChainBackend
} from '../../src/lightning/chain/chain-watcher';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { ISpliceInFlight } from '../../src/lightning/channel/channel-state';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { buildLocalCommitment } from '../../src/lightning/channel/commitment-builder';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';

bitcoin.initEccLib(ecc);

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`splice-below-lock-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		const priv = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(getPublicKey(priv));
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

/** A backend with a controllable script-hash history that records broadcasts. */
class ControlledBackend implements IChainBackend {
	broadcasts: string[] = [];
	history: Array<{ txid: string; height: number }> = [];
	headerCallback: ((height: number) => void) | null = null;
	async subscribeToHeaders(cb: (height: number) => void): Promise<void> {
		this.headerCallback = cb;
	}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return this.history;
	}
	async getTransaction(): Promise<Buffer> {
		throw new Error('not needed');
	}
	async broadcastTransaction(hex: string): Promise<string> {
		this.broadcasts.push(hex);
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

const tick = (ms = 25): Promise<void> => new Promise((r) => setTimeout(r, ms));

const display = (txid: Buffer): string =>
	Buffer.from(txid).reverse().toString('hex');

describe('Issue #764: a splice on chain below its lock depth', function () {
	this.timeout(10_000);

	describe('the funding watch reports being mined and reaching depth apart', () => {
		const channelId = Buffer.alloc(32, 9);
		const spliceTxid = '33'.repeat(32);
		const fundingScript = Buffer.from('0020' + '44'.repeat(32), 'hex');
		let backend: ControlledBackend;
		let watcher: ChainWatcher;
		let seen: Array<{ txid: string; height: number }>;
		let unseen: string[];
		let confirmed: string[];

		beforeEach(async () => {
			backend = new ControlledBackend();
			const channelManager = new ChannelManager({
				localBasepoints: makeBasepoints(makeSeed(1)),
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: crypto.randomBytes(32)
			});
			channelManager.on('error', () => {});
			watcher = new ChainWatcher({
				backend,
				channelManager,
				missingDebounceMs: 0
			});
			watcher.on('error', () => {});
			seen = [];
			unseen = [];
			confirmed = [];
			watcher.on('funding:seen', (_id: Buffer, txid: string, height: number) =>
				seen.push({ txid, height })
			);
			watcher.on('funding:unseen', (_id: Buffer, txid: string) =>
				unseen.push(txid)
			);
			watcher.on('funding:confirmed', (_id: Buffer, txid: string) =>
				confirmed.push(txid)
			);
			await watcher.start();
		});

		afterEach(() => watcher.stop());

		async function recheck(): Promise<void> {
			watcher.recheckAllWatches();
			await tick();
		}

		it('reports one confirmation of a depth-3 watch as seen, not confirmed', async () => {
			backend.headerCallback!(100);
			backend.history = [{ txid: spliceTxid, height: 100 }];
			await watcher.watchFundingOutput(
				channelId,
				spliceTxid,
				0,
				3,
				fundingScript
			);
			await tick();

			expect(seen, 'mined at 100, one confirmation').to.deep.equal([
				{ txid: spliceTxid, height: 100 }
			]);
			expect(confirmed, 'the lock depth is not reached').to.deep.equal([]);
			// A repeated scan at the same height is not a new fact.
			await recheck();
			expect(seen.length).to.equal(1);

			backend.headerCallback!(102);
			await tick();
			expect(confirmed, 'three deep: the lock may go').to.deep.equal([
				spliceTxid
			]);
		});

		it('retracts the sighting when the transaction falls back to the mempool', async () => {
			backend.headerCallback!(100);
			backend.history = [{ txid: spliceTxid, height: 100 }];
			await watcher.watchFundingOutput(
				channelId,
				spliceTxid,
				0,
				3,
				fundingScript
			);
			await tick();
			expect(seen.length).to.equal(1);

			// Reorged out: still relayable, so it is back in the mempool.
			backend.history = [{ txid: spliceTxid, height: 0 }];
			await recheck();
			expect(unseen, 'the confirmation is taken back').to.deep.equal([
				spliceTxid
			]);
			// Edge-triggered: an unconfirmed tx that stays unconfirmed says
			// nothing new.
			await recheck();
			expect(unseen.length).to.equal(1);

			// Re-mined in another block: a new height is a new fact.
			backend.history = [{ txid: spliceTxid, height: 101 }];
			await recheck();
			expect(seen).to.deep.equal([
				{ txid: spliceTxid, height: 100 },
				{ txid: spliceTxid, height: 101 }
			]);
		});

		it('retracts a sighting the transaction disappears from entirely', async () => {
			backend.headerCallback!(100);
			backend.history = [{ txid: spliceTxid, height: 100 }];
			await watcher.watchFundingOutput(
				channelId,
				spliceTxid,
				0,
				3,
				fundingScript
			);
			await tick();
			expect(seen.length).to.equal(1);

			backend.history = [];
			// Behind the same three-check debounce the missing alarm uses: a
			// single empty answer from one server is not a verdict.
			await recheck();
			await recheck();
			expect(unseen, 'not on the first two absences').to.deep.equal([]);
			await recheck();
			expect(unseen).to.deep.equal([spliceTxid]);
		});
	});

	describe('the close a node can build in the window', () => {
		/** The peer funding key the grafted record's commitment signature uses. */
		const PEER_FUNDING_PRIV = crypto
			.createHash('sha256')
			.update(Buffer.from('splice-below-lock-peer-funding'))
			.digest();

		interface IFixture {
			alice: LightningNode;
			bob: LightningNode;
			channelId: Buffer;
			backend: ControlledBackend;
			fundingTxid: Buffer;
			destroy: () => void;
		}

		async function setup(seedBase: number): Promise<IFixture> {
			const backend = new ControlledBackend();
			const configA = makeNodeConfig(seedBase);
			configA.chainBackend = backend;
			const alice = new LightningNode(configA);
			const bob = new LightningNode(makeNodeConfig(seedBase + 1));
			for (const node of [alice, bob]) {
				node.on('error', () => {});
				node.on('node:error', () => {});
			}
			alice.on('message:outbound', (pubkey, type, payload) => {
				if (pubkey === bob.getNodeId())
					bob.handlePeerMessage(alice.getNodeId(), type, payload);
			});
			bob.on('message:outbound', (pubkey, type, payload) => {
				if (pubkey === alice.getNodeId())
					alice.handlePeerMessage(bob.getNodeId(), type, payload);
			});

			const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
			const fundingTxid = crypto
				.createHash('sha256')
				.update(`splice-below-lock-funding-${seedBase}`)
				.digest();
			const channelId = alice.createFunding(
				channel,
				fundingTxid,
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			await tick(60); // let the chain watcher auto-start

			return {
				alice,
				bob,
				channelId,
				backend,
				fundingTxid,
				destroy: (): void => {
					alice.destroy();
					bob.destroy();
				}
			};
		}

		/**
		 * The peer's signature over the local commitment the grafted record
		 * adopts to, built through the channel's OWN adoption view so it tracks
		 * whatever that view does to the outpoint, capacity and balances.
		 */
		function signAdoptedCommitment(
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			channel: any,
			peer: ChannelSigner
		): Buffer {
			const view = {
				...channel.getFullState(),
				...channel._computeSpliceAdoption()
			};
			const built = buildLocalCommitment(
				view,
				perCommitmentPointFromSecret(
					generateFromSeed(
						view.localPerCommitmentSeed,
						MAX_INDEX - view.localCommitmentNumber
					)
				),
				undefined,
				true
			);
			return peer.signCommitmentTx(
				built.result.tx,
				built.fundingWitnessScript,
				built.fundingAmount
			);
		}

		/**
		 * Graft a session-free point-of-no-return record for a DEPTH-LOCKED
		 * splice: the only shape the adoption path judges, and the one a restart
		 * or a mid-splice channel failure leaves behind. A real splice needs a
		 * full interactive negotiation.
		 */
		function graftDepthLockedSplice(
			node: LightningNode,
			channelId: Buffer
		): Buffer {
			const channel = node.getChannelManager().getChannel(channelId)!;
			const spliceTxid = crypto.randomBytes(32);
			const peer = new ChannelSigner(PEER_FUNDING_PRIV);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const raw = channel.getFullState() as any;
			raw.spliceInFlight = {
				spliceTxid,
				newFundingOutputIndex: 0,
				newFundingSatoshis: 1_000_000n,
				spliceTxHex: '',
				fullySigned: true,
				isInitiator: true,
				localRelativeSatoshis: 0n,
				remoteRelativeSatoshis: 0n,
				remoteFundingPubkey: peer.fundingPubkey,
				ourSharedInputSig: Buffer.alloc(64),
				ourWalletWitnesses: [],
				ourWalletInputIndices: [],
				inputPrevouts: [],
				remoteCommitmentSig: Buffer.alloc(64),
				sentTxSignatures: true,
				receivedTxSignatures: true,
				localSpliceLocked: false,
				remoteSpliceLocked: false,
				confirmed: false,
				lockAtDepth: 3
			};
			raw.spliceInFlight.remoteCommitmentSig = signAdoptedCommitment(
				channel,
				peer
			);
			return spliceTxid;
		}

		function record(
			node: LightningNode,
			channelId: Buffer
		): ISpliceInFlight | null {
			return (
				node.getChannelManager().getChannel(channelId)!.getFullState()
					.spliceInFlight ?? null
			);
		}

		function destScript(node: LightningNode): Buffer {
			return bitcoin.payments.p2wpkh({
				pubkey: Buffer.from(node.getNodeId(), 'hex')
			}).output!;
		}

		function lastBroadcastSpends(fx: IFixture): Buffer {
			const tx = bitcoin.Transaction.fromHex(
				fx.backend.broadcasts[fx.backend.broadcasts.length - 1]
			);
			return Buffer.from(tx.ins[0].hash);
		}

		it('force closes onto the splice at one confirmation, without adopting it', async () => {
			const fx = await setup(7641);
			const spliceTxid = graftDepthLockedSplice(fx.alice, fx.channelId);

			fx.alice
				.getChainWatcher()!
				.emit('funding:seen', fx.channelId, display(spliceTxid), 500);
			await tick();

			expect(
				record(fx.alice, fx.channelId)!.confirmedHeight,
				'the height is stamped'
			).to.equal(500);
			expect(
				record(fx.alice, fx.channelId)!.confirmed,
				'but the lock is still owed'
			).to.equal(false);

			const forced = fx.alice.forceCloseChannel(
				fx.channelId,
				destScript(fx.alice)
			);
			expect(forced.ok, forced.error).to.equal(true);

			expect(
				lastBroadcastSpends(fx).equals(spliceTxid),
				'the close spends the splice funding'
			).to.equal(true);
			const state = fx.alice
				.getChannelManager()
				.getChannel(fx.channelId)!
				.getFullState();
			expect(
				state.fundingTxid!.equals(fx.fundingTxid),
				'the channel is left on the pre-splice funding'
			).to.equal(true);
			expect(state.spliceInFlight, 'the record is not consumed').to.not.equal(
				null
			);
			expect(
				state.closeSpendsSpliceTxid!.equals(spliceTxid),
				'which funding the broadcast close spends is recorded'
			).to.equal(true);
			fx.destroy();
		});

		it('re-drives an already broadcast close when the splice is mined', async () => {
			const fx = await setup(7651);
			const forced = fx.alice.forceCloseChannel(
				fx.channelId,
				destScript(fx.alice)
			);
			expect(forced.ok, forced.error).to.equal(true);
			const spliceTxid = graftDepthLockedSplice(fx.alice, fx.channelId);
			const before = fx.backend.broadcasts.length;

			fx.alice
				.getChainWatcher()!
				.emit('funding:seen', fx.channelId, display(spliceTxid), 500);
			await tick();

			expect(fx.backend.broadcasts.length, 'a new close went out').to.equal(
				before + 1
			);
			expect(
				lastBroadcastSpends(fx).equals(spliceTxid),
				'on the funding the chain has'
			).to.equal(true);
			// Repeating the sighting does not repeat the broadcast: the close on
			// the network already spends this splice.
			fx.alice
				.getChainWatcher()!
				.emit('funding:seen', fx.channelId, display(spliceTxid), 500);
			await tick();
			expect(fx.backend.broadcasts.length).to.equal(before + 1);
			fx.destroy();
		});

		it('goes back to the pre-splice funding when the confirmation is reorged out', async () => {
			const fx = await setup(7661);
			const spliceTxid = graftDepthLockedSplice(fx.alice, fx.channelId);
			fx.alice
				.getChainWatcher()!
				.emit('funding:seen', fx.channelId, display(spliceTxid), 500);
			await tick();
			expect(
				fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice)).ok
			).to.equal(true);
			expect(lastBroadcastSpends(fx).equals(spliceTxid)).to.equal(true);
			const before = fx.backend.broadcasts.length;

			fx.alice
				.getChainWatcher()!
				.emit('funding:unseen', fx.channelId, display(spliceTxid));
			await tick();

			expect(
				record(fx.alice, fx.channelId)!.confirmedHeight,
				'the sighting is retracted'
			).to.equal(undefined);
			expect(fx.backend.broadcasts.length, 'the close is re-driven').to.equal(
				before + 1
			);
			expect(
				lastBroadcastSpends(fx).equals(fx.fundingTxid),
				'onto the funding that is unspent again'
			).to.equal(true);
			const state = fx.alice
				.getChannelManager()
				.getChannel(fx.channelId)!
				.getFullState();
			expect(
				state.closeSpendsSpliceTxid,
				'the close no longer spends a splice'
			).to.equal(null);
			fx.destroy();
		});

		it('adopts for real once the splice reaches its lock depth', async () => {
			const fx = await setup(7671);
			const spliceTxid = graftDepthLockedSplice(fx.alice, fx.channelId);
			fx.alice
				.getChainWatcher()!
				.emit('funding:seen', fx.channelId, display(spliceTxid), 500);
			await tick();
			expect(
				fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice)).ok
			).to.equal(true);
			const provisional =
				fx.backend.broadcasts[fx.backend.broadcasts.length - 1];

			fx.alice
				.getChainWatcher()!
				.emit('funding:confirmed', fx.channelId, display(spliceTxid));
			await tick();

			const state = fx.alice
				.getChannelManager()
				.getChannel(fx.channelId)!
				.getFullState();
			expect(state.spliceInFlight, 'the record is consumed now').to.equal(null);
			expect(
				state.fundingTxid!.equals(spliceTxid),
				'and the channel has moved onto the splice'
			).to.equal(true);
			expect(
				state.closeSpendsSpliceTxid,
				'the marker retires with the adoption'
			).to.equal(null);
			expect(
				fx.backend.broadcasts[fx.backend.broadcasts.length - 1],
				'the same commitment, re-broadcast'
			).to.equal(provisional);
			fx.destroy();
		});

		it('refuses a conflict verdict for a splice the chain has taken', async () => {
			const fx = await setup(7681);
			const spliceTxid = graftDepthLockedSplice(fx.alice, fx.channelId);
			fx.alice
				.getChainWatcher()!
				.emit('funding:seen', fx.channelId, display(spliceTxid), 500);
			await tick();

			const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
			expect(
				channel.markSpliceConflicted({
					txid: '55'.repeat(32),
					height: 499,
					inputIndex: 1
				}),
				'a splice in a block cannot also have a winning conflict'
			).to.equal(false);
			expect(record(fx.alice, fx.channelId)!.conflict).to.equal(undefined);
			fx.destroy();
		});

		it('refuses to revert a conflicted splice the chain then took', async () => {
			const fx = await setup(7691);
			const spliceTxid = graftDepthLockedSplice(fx.alice, fx.channelId);
			const channel = fx.alice.getChannelManager().getChannel(fx.channelId)!;
			// The verdict lands first, while the splice is nowhere; then a reorg
			// puts the splice in a block instead. The revert must not run: it
			// would abandon the only funding output the channel has left.
			expect(
				channel.markSpliceConflicted({
					txid: '66'.repeat(32),
					height: 499,
					inputIndex: 1
				})
			).to.equal(true);
			fx.alice
				.getChainWatcher()!
				.emit('funding:seen', fx.channelId, display(spliceTxid), 500);
			await tick();

			const refusal = channel.revertConflictedSplice()[0] as {
				message: string;
			};
			expect(refusal.message).to.contain('the splice tx confirmed');
			expect(
				record(fx.alice, fx.channelId),
				'the record survives the refusal'
			).to.not.equal(null);
			fx.destroy();
		});
	});
});
