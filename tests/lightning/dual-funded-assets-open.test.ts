import { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../src/utils/ecc';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import { decodeAssetOpenFrame } from '../../src/lightning/message/asset-open';
import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { mnemonicToSeedSync } from 'bip39';
import { nodeStorageView } from '../../src/cli/node-storage-view';
import type {
	IAuxiliaryDualFunding,
	IAssetOpenContext
} from '../../src/lightning/channel/asset-opening-provider';
import { ASSET_OPENING_TYPE_HEX } from '../../src/lightning/features/asset-opening';
import { FeatureFlags } from '../../src/lightning/features/flags';
import { Network } from '../../src/lightning/invoice/types';
import { bip32RootFromSeed } from '../../src/lightning/keys/wallet-keys';
import {
	decodeOpenChannel2Message,
	decodeAcceptChannel2Message,
	encodeOpenChannel2Message
} from '../../src/lightning/message/dual-funding';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { IFundingProvider } from '../../src/lightning/node/types';
import { bindFinalDaemonView } from '../../src/lightning/storage/final-daemon-admission';
import { generateFinalDaemonWallet } from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	TestChain,
	TestChainBackend,
	electrumScriptHash
} from './helpers/auxiliary-chain';
import { referenceProvider } from './helpers/auxiliary-pair';

function open(node: LightningNode, peer: LightningNode) {
	const options = {
		dualFundedAssets: true,
		fundingSatoshis: 400_000n,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 1000
	};
	return node.openChannelV2(peer.getNodeId(), options);
}

function host(
	chain: TestChain,
	enrolled: boolean,
	answer?: bigint,
	hooks?: Partial<IAuxiliaryDualFunding>
) {
	const dir = mkdtempSync(join(tmpdir(), 'asset-v2-'));
	const fresh = generateFinalDaemonWallet(false, enrolled);
	const db = SqliteStorage.createFinalWallet(
		join(dir, 'lightning.db'),
		fresh.binding
	);
	const seed = mnemonicToSeedSync(fresh.mnemonic);
	const storage = nodeStorageView(db) as SqliteStorage;
	const chainBackend = Object.assign(new TestChainBackend(chain), {
		async listUnspent(hash: string) {
			return chain
				.history(hash)
				.flatMap(({ txid, height }) =>
					chain
						.transaction(txid)!
						.outs.flatMap((out, outputIndex) =>
							electrumScriptHash(out.script) === hash &&
							chain.output(txid, outputIndex)
								? [{ txid, outputIndex, height, valueSat: out.value }]
								: []
						)
				);
		}
	});
	const calls: string[] = [];
	const proposals: IAssetOpenContext[] = [];
	const policy = (peer: string, initiator: boolean, opener: bigint) => {
		calls.push('policy:' + [peer, initiator, opener].join(':'));
		return answer;
	};
	const unexpected = async (): Promise<never> => {
		calls.push('unexpected signer');
		throw Error('Proposal must finish before any funding or exit signature');
	};
	const provider: IAuxiliaryDualFunding = {
		version: 1,
		contribution: policy,
		async abandon() {
			calls.push('abandoned');
		},
		async propose(ctx) {
			proposals.push(ctx);
			return Buffer.from(ctx.isInitiator ? 'alice' : 'bob');
		},
		async describe() {
			calls.push('declined proposal');
			throw Error('Asset proposals declined by test policy');
		},
		prepare: unexpected,
		signFunding: unexpected,
		signExits: unexpected,
		verifyExits: unexpected,
		confirmFunding: unexpected,
		retractFunding: unexpected,
		recoverOutput: unexpected,
		...hooks
	};
	const fundingProvider: IFundingProvider = {
		buildFundingTransaction: unexpected,
		broadcastTransaction: async (hex) => chainBackend.broadcastTransaction(hex),
		resolveFinalOpeningInputs: unexpected,
		supportsFixedOutputFees: () => true
	};
	bindFinalDaemonView(
		storage,
		bip32RootFromSeed(seed),
		fundingProvider,
		chainBackend
	);
	const node = LightningNode.fromMnemonic(fresh.mnemonic, {
		network: Network.REGTEST,
		seed,
		storage,
		chainBackend,
		fundingProvider,
		peerStorageEnabled: false,
		auxiliaryChannels: {
			provider: referenceProvider(),
			resolveIncoming: () => undefined,
			dualFunding: provider
		}
	});
	const errors: string[] = [];
	node.getChannelManager().on('error', (_id, message) => errors.push(message));
	const sent: { type: number; payload: Buffer }[] = [];
	node.on('message:outbound', (_peer, type, payload) =>
		sent.push({ type, payload })
	);
	return {
		node,
		chainBackend,
		db,
		errors,
		calls,
		sent,
		proposals,
		close() {
			node.destroy();
			chainBackend.close();
			db.close();
			rmSync(dir, { recursive: true, force: true });
		}
	};
}

function announce(node: LightningNode, remote: FeatureFlags) {
	// The transport supplies these init vectors before delivering channel messages.
	(node as unknown as { peerInitFeatures(): FeatureFlags }).peerInitFeatures =
		() => remote;
}

// This host signs real Bitcoin inputs. The independent regtest host verifies the asset proofs.
function signedHosts(chain: TestChain) {
	const fundingRoot = Buffer.alloc(32, 5),
		keys = [Buffer.alloc(32, 41), Buffer.alloc(32, 42)];
	const previous = keys.map((key, side) => {
		const prev = new Transaction();
		prev.addInput(Buffer.alloc(32, 3 + side), 0);
		prev.addOutput(
			Buffer.concat([
				Buffer.from('5120', 'hex'),
				Buffer.from(ecc.pointFromScalar(key, true)!).subarray(1)
			]),
			side === 0 ? 401000 : 201000
		);
		chain.seed(prev);
		return prev;
	});
	const inputs = previous.map((tx, i) => ({
		serialId: BigInt(i),
		prevTx: tx.toBuffer(),
		txid: tx.getHash(),
		vout: 0,
		sequence: 0xfffffffd
	}));
	const outputs = [
		{
			serialId: 2n,
			kind: 'funding' as const,
			valueSats: 600000n,
			descriptorHash: fundingRoot
		}
	];
	return [0, 1].map((side) =>
		host(chain, true, side === 0 ? 400000n : 200000n, {
			async describe() {
				return { inputs, outputs };
			},
			async prepare(ctx, _proposals, digest) {
				const tx = new Transaction();
				tx.version = 2;
				tx.locktime = ctx.open.locktime;
				for (const i of inputs) tx.addInput(i.txid, i.vout, i.sequence);
				tx.addOutput(
					createTaprootFundingScript(
						ctx.open.fundingPubkey,
						ctx.accept.fundingPubkey,
						undefined,
						fundingRoot
					).p2trOutput,
					600000
				);
				return {
					digest,
					async consent() {
						return Buffer.alloc(64, side + 1);
					},
					async authorize() {
						return Buffer.of(side + 1);
					},
					async finalize() {
						return {
							transaction: tx.toBuffer(),
							fundingRoot,
							proofDigest: Buffer.alloc(32, 6),
							fundingProofs: Buffer.of(7)
						};
					}
				};
			},
			async signExits() {
				return Buffer.of(42 + side);
			},
			async recoverOutput(ctx) {
				const tx = new Transaction();
				tx.version = 2;
				tx.addInput(ctx.parent.getHash(), ctx.outputIndex, ctx.delay);
				tx.addOutput(
					Buffer.concat([
						Buffer.from('0014', 'hex'),
						Buffer.alloc(20, side + 1)
					]),
					ctx.parent.outs[ctx.outputIndex].value - 1000
				);
				tx.setWitness(0, ctx.signSweep(tx, [ctx.parent]));
				return tx;
			},
			async retractFunding() {},
			async confirmFunding() {},
			async verifyExits(_ctx, shares) {
				expect(shares.map((b) => b[0])).to.deep.equal([42, 43]);
				const exit = {
					toLocal: { script: '6a0141' },
					toRemote: { script: '6a0142' },
					proofs: '01'
				};
				return { local: exit, remote: exit };
			},
			async signFunding(_candidate, _proofs, tx, indices, prevouts) {
				expect(indices).to.deep.equal([side]);
				return indices.map((i) => [
					Buffer.from(
						ecc.signSchnorr(
							tx.hashForWitnessV1(
								i,
								prevouts.scripts,
								prevouts.values.map(Number),
								0
							),
							keys[side]
						)
					)
				]);
			}
		})
	);
}

describe('Dual-funded asset channel opening through openChannelV2', function () {
	it('requires opt-in at both endpoints before reserving a key or invoking the asset policy', function () {
		const chain = new TestChain();
		const alice = host(chain, true, 400_000n);
		const bob = host(chain, false, 200_000n);
		try {
			announce(alice.node, bob.node.getLocalFeatures());
			announce(bob.node, alice.node.getLocalFeatures());
			expect(bob.node.getLocalFeatures().hasBit(457)).to.equal(false);
			bob.node.getLocalFeatures().setBit(457);
			expect(bob.node.getLocalFeatures().hasBit(457)).to.equal(false);
			for (const [from, to] of [
				[alice, bob],
				[bob, alice]
			]) {
				const manager = from.node.getChannelManager();
				const index = manager.nextChannelIndex;
				expect(() => open(from.node, to.node)).to.throw();
				expect(manager.nextChannelIndex).to.equal(index);
				expect(from.sent).to.be.empty;
				expect(from.calls).to.be.empty;
			}
		} finally {
			bob.close();
			alice.close();
		}
	});

	it('refuses public wire offers and an unfunded local policy before allocating a responder key', function () {
		const chain = new TestChain();
		const alice = host(chain, true, 400_000n);
		const bob = host(chain, true);
		try {
			announce(alice.node, bob.node.getLocalFeatures());
			announce(bob.node, alice.node.getLocalFeatures());
			open(alice.node, bob.node);
			const offer = alice.sent.find(
				(m) => m.type === MessageType.OPEN_CHANNEL2
			)!;
			const terms = decodeOpenChannel2Message(offer.payload);
			const manager = bob.node.getChannelManager();
			const index = manager.nextChannelIndex;
			for (const channelFlags of [1, 0]) {
				bob.node.handlePeerMessage(
					alice.node.getNodeId(),
					offer.type,
					encodeOpenChannel2Message({ ...terms, channelFlags })
				);
				expect(manager.nextChannelIndex).to.equal(index);
				expect(manager.listChannels()).to.be.empty;
				expect(
					bob.sent.some((m) => m.type === MessageType.ACCEPT_CHANNEL2)
				).to.equal(false);
				expect(bob.proposals).to.be.empty;
			}
			expect(bob.calls.filter((c) => c.startsWith('policy:'))).to.have.length(
				1
			);
		} finally {
			bob.close();
			alice.close();
		}
	});

	it('negotiates private positive-depth funding from both wallets and stops before signing when a proposal fails', async function () {
		const chain = new TestChain();
		const alice = host(chain, true, 400_000n);
		const bob = host(chain, true, 200_000n);
		try {
			announce(alice.node, bob.node.getLocalFeatures());
			announce(bob.node, alice.node.getLocalFeatures());
			open(alice.node, bob.node);
			const offer = alice.sent.find(
				(m) => m.type === MessageType.OPEN_CHANNEL2
			)!;
			const terms = decodeOpenChannel2Message(offer.payload);
			expect(terms.channelType?.toString('hex')).to.equal(
				ASSET_OPENING_TYPE_HEX
			);
			expect(
				FeatureFlags.fromBuffer(terms.channelType!).listSetBits()
			).to.have.members([456, 2026]);
			expect(terms.channelFlags).to.equal(0);
			expect(terms.fundingSatoshis).to.equal(400_000n);
			bob.node.handlePeerMessage(
				alice.node.getNodeId(),
				offer.type,
				offer.payload
			);
			const reply = bob.sent.find(
				(m) => m.type === MessageType.ACCEPT_CHANNEL2
			)!;
			const accepted = decodeAcceptChannel2Message(reply.payload);
			expect(accepted.channelType).to.deep.equal(terms.channelType);
			expect(accepted.minimumDepth).to.be.greaterThan(0);
			expect(accepted.fundingSatoshis).to.equal(200_000n);
			// Deliver complete turns in wire order. One test host refuses in describe.
			let deliveredAlice = 1;
			let deliveredBob = 0;
			for (let turn = 0; turn < 12; turn++) {
				for (const msg of bob.sent.slice(deliveredBob)) {
					deliveredBob++;
					alice.node.handlePeerMessage(
						bob.node.getNodeId(),
						msg.type,
						msg.payload
					);
				}
				for (const msg of alice.sent.slice(deliveredAlice)) {
					deliveredAlice++;
					bob.node.handlePeerMessage(
						alice.node.getNodeId(),
						msg.type,
						msg.payload
					);
				}
				await new Promise<void>((done) => setImmediate(done));
			}
			expect(alice.proposals.map((p) => p.isInitiator)).to.deep.equal([true]);
			expect(bob.proposals.map((p) => p.isInitiator)).to.deep.equal([false]);
			expect(alice.proposals[0].attempt).to.deep.equal(
				bob.proposals[0].attempt
			);
			expect(alice.proposals[0].channelId).to.deep.equal(
				bob.proposals[0].channelId
			);
			expect(alice.calls).to.include(
				'policy:' + [bob.node.getNodeId(), true, 400_000n].join(':')
			);
			expect(bob.calls).to.include(
				'policy:' + [alice.node.getNodeId(), false, 400_000n].join(':')
			);
			expect([...alice.calls, ...bob.calls]).not.to.include(
				'unexpected signer'
			);
			expect([...alice.calls, ...bob.calls]).to.include('declined proposal');
			const types = [...alice.sent, ...bob.sent].map((m) => m.type);
			expect(types).not.to.include(MessageType.TX_SIGNATURES);
			expect(types).not.to.include(MessageType.COMMITMENT_SIGNED);
			expect(types).not.to.include(MessageType.CHANNEL_READY);
		} finally {
			bob.close();
			alice.close();
		}
	});
	for (const interrupt of [false, true]) {
		it(
			'funds from both original wallets' +
				(interrupt
					? ' after the final exit share is lost'
					: ' over the live v2 opening'),
			async function () {
				this.timeout(90000);
				const chain = new TestChain(),
					[alice, bob] = signedHosts(chain);
				const owners = [alice, bob],
					sent = [0, 0];
				const daemons = owners.map((o): BeignetNode => {
					const daemon = Object.create(BeignetNode.prototype) as BeignetNode;
					Object.assign(daemon, {
						node: o.node,
						wallet: { getBalance: (): number => 0, transactions: {} }
					});
					return daemon;
				});
				const releases = owners.map((o) => {
					let release!: () => void;
					const gate = new Promise<void>((done) => {
						release = done;
					});
					const hand = o.chainBackend.broadcastTransaction.bind(o.chainBackend);
					o.chainBackend.broadcastTransaction = async (
						hex
					): Promise<string> => {
						await gate;
						return hand(hex);
					};
					return release;
				});
				const tick = (): Promise<void> =>
					new Promise<void>((done) => setImmediate(done));
				let drop = interrupt,
					resumed = false,
					admittedOnce = false;
				try {
					announce(alice.node, bob.node.getLocalFeatures());
					announce(bob.node, alice.node.getLocalFeatures());
					await Promise.all(owners.map((o) => o.node.startChainWatcher()));
					open(alice.node, bob.node);
					for (let n = 0; n < 60; n++) {
						const count = alice.sent.length + bob.sent.length;
						for (const side of [0, 1]) {
							const here = owners[side],
								peer = owners[1 - side];
							for (const msg of here.sent.slice(sent[side])) {
								sent[side]++;
								if (
									drop &&
									side === 0 &&
									msg.type === BEIGNET_CUSTOM_MESSAGE_TYPE
								) {
									const custom = decodeCustomMessage(msg.payload);
									if (
										custom.subtype === 96 &&
										decodeAssetOpenFrame(custom.payload).phase === 'exit'
									)
										continue;
								}
								if (drop && msg.type === MessageType.COMMITMENT_SIGNED)
									continue;
								peer.node.handlePeerMessage(
									here.node.getNodeId(),
									msg.type,
									msg.payload
								);
							}
						}
						await new Promise<void>((done) => setImmediate(done));
						if (count === alice.sent.length + bob.sent.length && n > 1) break;
						const has = owners.map((o) => o.db.loadFinalOpenings().length > 0);
						if (drop && has[0] && !has[1]) {
							admittedOnce = true;
							drop = false;
							resumed = true;
							for (const [i, o] of owners.entries()) {
								sent[i] = o.sent.length;
								o.node
									.getChannelManager()
									.handlePeerDisconnected(owners[1 - i].node.getNodeId());
							}
							for (const [i, o] of owners.entries())
								o.node
									.getChannelManager()
									.handlePeerReconnected(owners[1 - i].node.getNodeId());
						}
						if (
							has.every(Boolean) &&
							owners.every((o) =>
								o.db.loadFinalFundingTransaction(
									o.db.loadFinalOpenings()[0].channelId
								)
							)
						)
							break;
					}
					expect(resumed).to.equal(interrupt);
					expect(admittedOnce).to.equal(interrupt);
					for (const o of owners) expect(o.errors).to.deep.equal([]);
					const funds = owners.map((o, i) => {
						const cs = o.db.loadFinalOpenings();
						expect(cs).to.have.length(1);
						const candidate = cs[0];
						const view = o.node
							.listChannels()
							.find(
								(ch) => ch.channelId.toString('hex') === candidate.channelId
							)!;
						expect(view.auxiliary).to.equal(true);
						expect(view.htlcUsable).to.equal(false);
						expect(view.spendableOutboundMsat).to.equal(0n);
						expect(o.node.getLiquiditySnapshot().totalCapacitySats).to.equal(0);
						const daemon = daemons[i];
						expect(daemon.listChannels()[0]).to.include({
							auxiliary: true,
							maxSendableSats: 0
						});
						expect(daemon.canSend(1).availableSats).to.equal(0);
						expect(daemon.canReceive(1).availableSats).to.equal(0);

						expect(
							o.db.loadFinalOpeningExit(candidate.channelId)
						).to.be.instanceof(Buffer);
						const raw = o.db.loadFinalFundingTransaction(candidate.channelId);
						expect(raw).to.be.instanceof(Buffer);
						return Transaction.fromBuffer(raw!);
					});
					expect(funds[0].toHex()).to.equal(funds[1].toHex());
					expect(
						daemons.map((d) => d.getBalance().assetChannelSats),
						'both signed only'
					).to.deep.equal([undefined, undefined]);
					releases[0]();
					await tick();
					expect(
						daemons.map((d) => d.getBalance().assetChannelSats),
						'only Alice has a broadcast receipt'
					).to.deep.equal([400000, undefined]);
					chain.mine(funds[0]);
					await tick();
					expect(
						daemons.map((d) => d.getBalance().assetChannelSats),
						'both saw funding in a block'
					).to.deep.equal([400000, 200000]);
					if (!interrupt) {
						const hash = electrumScriptHash(funds[0].outs[0].script);
						const restores = owners.map((o) => {
							const history = o.chainBackend.getScriptHashHistory.bind(
								o.chainBackend
							);
							const unspent = o.chainBackend.listUnspent.bind(o.chainBackend);
							o.chainBackend.getScriptHashHistory = async (sh) =>
								sh === hash ? [] : history(sh);
							o.chainBackend.listUnspent = async (sh) =>
								sh === hash ? [] : unspent(sh);
							o.chainBackend.announceBlock(chain.height);
							return () => {
								o.chainBackend.getScriptHashHistory = history;
								o.chainBackend.listUnspent = unspent;
								o.chainBackend.announceBlock(chain.height);
							};
						});
						await tick();
						expect(
							daemons.map((d) => d.getBalance().assetChannelSats),
							'funding orphaned and absent from the mempool'
						).to.deep.equal([undefined, undefined]);
						for (const restore of restores) restore();
						await tick();
						expect(
							daemons.map((d) => d.getBalance().assetChannelSats),
							'the same funding mined again'
						).to.deep.equal([400000, 200000]);
					}
					releases[1]();
					await tick();
					const id = alice.db.loadFinalOpenings()[0].channelId;
					const holder = interrupt ? bob : alice;
					chain.mine(
						Transaction.fromBuffer(holder.db.loadFinalOpeningExit(id)!)
					);
					await tick();
					expect(
						daemons.map((d) => d.getBalance().assetChannelClosingSats),
						'remote payout in mempool and local payout delayed'
					).to.deep.equal([400000, 200000]);
					expect(
						daemons.map((d) => d.getBalance().assetChannelSats)
					).to.deep.equal([undefined, undefined]);
					chain.mine();
					await tick();
					expect(
						daemons.map((d) => d.getBalance().assetChannelClosingSats),
						'only the exact mined wallet payout retires'
					).to.deep.equal(
						interrupt ? [undefined, 200000] : [400000, undefined]
					);
				} finally {
					bob.close();
					alice.close();
				}
			}
		);
	}
});
