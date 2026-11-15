/**
 * Closed third-party channels leave the routing graph on chain evidence
 * (issue #2048): a payment failure or a route's first use checks the
 * funding output, a spent channel stops being routed over, takes only
 * disabling updates, and is forgotten 72 blocks after the spend or as soon
 * as its splice is announced.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { findRoute } from '../../src/lightning/gossip/pathfinding';
import { MissionControl } from '../../src/lightning/gossip/mission-control';
import {
	CHANNEL_FLAG_DISABLED,
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	IGraphChannel,
	SPENT_CHANNEL_FORGET_DEPTH,
	decodeShortChannelId
} from '../../src/lightning/gossip/types';
import { encodeShortChannelId } from '../../src/lightning/gossip';
import {
	IChainBackend,
	MAX_FUNDING_SPEND_LOOKUPS,
	computeScriptHash,
	findAnnouncedChannelSpend
} from '../../src/lightning/chain/chain-watcher';
import { createFundingScript } from '../../src/lightning/script/funding';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IStructuredLog,
	PaymentStatus
} from '../../src/lightning/node/types';
import { UNKNOWN_NEXT_PEER } from '../../src/lightning/onion/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import {
	deserializeGraphChannel,
	serializeGraphChannel
} from '../../src/lightning/storage/serialization';

type TUnspent = Awaited<ReturnType<NonNullable<IChainBackend['listUnspent']>>>;

function pubkey(label: string): Buffer {
	return getPublicKey(
		crypto.createHash('sha256').update(`spent-${label}`).digest()
	);
}

function scidAt(block: number, txIndex = 1): Buffer {
	return encodeShortChannelId({ block, txIndex, outputIndex: 0 });
}

function announcement(
	scid: Buffer,
	a: Buffer,
	b: Buffer,
	chainHash: Buffer = REGTEST_CHAIN_HASH
): IChannelAnnouncementMessage {
	const [nodeId1, nodeId2] = Buffer.compare(a, b) < 0 ? [a, b] : [b, a];
	return {
		nodeSignature1: Buffer.alloc(64, 1),
		nodeSignature2: Buffer.alloc(64, 1),
		bitcoinSignature1: Buffer.alloc(64, 1),
		bitcoinSignature2: Buffer.alloc(64, 1),
		features: Buffer.alloc(0),
		chainHash,
		shortChannelId: scid,
		nodeId1,
		nodeId2,
		bitcoinKey1: pubkey(`btc1-${scid.toString('hex')}`),
		bitcoinKey2: pubkey(`btc2-${scid.toString('hex')}`)
	};
}

function update(
	scid: Buffer,
	direction: 0 | 1,
	opts: { disabled?: boolean; timestamp?: number; chainHash?: Buffer } = {}
): IChannelUpdateMessage {
	return {
		signature: Buffer.alloc(64, 1),
		chainHash: opts.chainHash ?? REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: opts.timestamp ?? Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: direction | (opts.disabled ? CHANNEL_FLAG_DISABLED : 0),
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 100,
		htlcMaximumMsat: 1_000_000_000n
	};
}

function addChannel(
	graph: NetworkGraph,
	scid: Buffer,
	a: Buffer,
	b: Buffer,
	chainHash: Buffer = REGTEST_CHAIN_HASH
): IChannelAnnouncementMessage {
	const ann = announcement(scid, a, b, chainHash);
	expect(graph.addChannelAnnouncement(ann, { verified: true })).to.equal(true);
	graph.applyChannelUpdate(update(scid, 0, { chainHash }), { verified: true });
	graph.applyChannelUpdate(update(scid, 1, { chainHash }), { verified: true });
	return ann;
}

/** A chain backend holding real funding and spending transactions. */
class FakeChain {
	private unspent = new Map<string, TUnspent>();
	private history = new Map<string, Array<{ txid: string; height: number }>>();
	private txs = new Map<string, Buffer>();
	private positions = new Map<string, number>();
	lookups = 0;

	fund(ann: IChannelAnnouncementMessage): { txid: string } {
		const scid = decodeShortChannelId(ann.shortChannelId);
		const script = createFundingScript(ann.bitcoinKey1, ann.bitcoinKey2);
		const tx = new bitcoin.Transaction();
		tx.addInput(crypto.randomBytes(32), 0);
		tx.addOutput(script.p2wshOutput, 100_000);
		const txid = tx.getId();
		const scriptHash = computeScriptHash(script.p2wshOutput);
		this.positions.set(txid, scid.txIndex);
		this.txs.set(txid, tx.toBuffer());
		this.history.set(scriptHash, [{ txid, height: scid.block }]);
		this.unspent.set(scriptHash, [
			{ txid, outputIndex: 0, valueSat: 100_000, height: scid.block }
		]);
		return { txid };
	}

	/** Spend the funding output at `height`, or only pay to its script. */
	spend(
		ann: IChannelAnnouncementMessage,
		height: number,
		opts: { unrelated?: boolean } = {}
	): void {
		const script = createFundingScript(ann.bitcoinKey1, ann.bitcoinKey2);
		const scriptHash = computeScriptHash(script.p2wshOutput);
		const funding = this.history.get(scriptHash)![0];
		const tx = new bitcoin.Transaction();
		if (opts.unrelated) {
			tx.addInput(crypto.randomBytes(32), 0);
			tx.addOutput(script.p2wshOutput, 1_000);
			this.unspent
				.get(scriptHash)!
				.push({ txid: tx.getId(), outputIndex: 0, valueSat: 1_000, height });
		} else {
			tx.addInput(Buffer.from(funding.txid, 'hex').reverse(), 0);
			tx.setWitness(0, [
				Buffer.alloc(0),
				Buffer.alloc(71, 1),
				Buffer.alloc(71, 2),
				script.witnessScript
			]);
			tx.addOutput(
				Buffer.concat([Buffer.from([0, 20]), Buffer.alloc(20)]),
				99_000
			);
			this.unspent.set(
				scriptHash,
				this.unspent.get(scriptHash)!.filter((u) => u.txid !== funding.txid)
			);
		}
		this.txs.set(tx.getId(), tx.toBuffer());
		this.history.get(scriptHash)!.push({ txid: tx.getId(), height });
	}

	backend(): IChainBackend {
		return {
			subscribeToHeaders: async (): Promise<void> => {},
			subscribeToScriptHash: async (): Promise<void> => {},
			getScriptHashHistory: async (
				scriptHash: string
			): Promise<Array<{ txid: string; height: number }>> => {
				this.lookups++;
				return [...(this.history.get(scriptHash) ?? [])];
			},
			getTransaction: async (txid: string): Promise<Buffer> => {
				this.lookups++;
				const raw = this.txs.get(txid);
				if (!raw) throw new Error('unknown transaction');
				return raw;
			},
			broadcastTransaction: async (): Promise<string> => {
				throw new Error('unused');
			},
			listUnspent: async (scriptHash: string): Promise<TUnspent> => {
				this.lookups++;
				return [...(this.unspent.get(scriptHash) ?? [])];
			},
			getTransactionMerkleProof: async (
				txid: string,
				height: number
			): Promise<{ blockHeight: number; txIndex: number }> => {
				this.lookups++;
				return { blockHeight: height, txIndex: this.positions.get(txid) ?? 0 };
			}
		};
	}
}

describe('Spent graph channels (issue #2048)', () => {
	const A = pubkey('a');
	const B = pubkey('b');
	const C = pubkey('c');
	const D = pubkey('d');

	/** A to C over X (direct) or over Y and Z through D. */
	function world(): {
		graph: NetworkGraph;
		evicted: string[];
		x: IChannelAnnouncementMessage;
		y: IChannelAnnouncementMessage;
	} {
		const evicted: string[] = [];
		const graph = new NetworkGraph(REGTEST_CHAIN_HASH, {
			onChannelEvicted: (scidHex): void => {
				evicted.push(scidHex);
			}
		});
		addChannel(graph, scidAt(400), A, B);
		const x = addChannel(graph, scidAt(500), B, C);
		const y = addChannel(graph, scidAt(501), B, D);
		addChannel(graph, scidAt(502), D, C);
		return { graph, evicted, x, y };
	}

	const route = (graph: NetworkGraph): string[] =>
		findRoute(graph, A, C, 10_000n, 40)!.hops.map((h) =>
			h.shortChannelId.toString('hex')
		);

	it('a spent channel is not routed over, from the moment it is marked', () => {
		const { graph, x, y } = world();
		expect(route(graph)[1]).to.equal(x.shortChannelId.toString('hex'));

		expect(graph.markChannelFundingSpent(x.shortChannelId, 990)).to.equal(true);
		expect(route(graph)[1]).to.equal(y.shortChannelId.toString('hex'));
	});

	it('takes only a disabling channel_update once spent', () => {
		const { graph, x } = world();
		graph.markChannelFundingSpent(x.shortChannelId, 990);
		const later = Math.floor(Date.now() / 1000) + 60;
		const enabled = update(x.shortChannelId, 0, { timestamp: later });
		expect(graph.wouldAcceptChannelUpdate(enabled)).to.equal(false);
		expect(graph.applyChannelUpdate(enabled, { verified: true })).to.equal(
			false
		);

		const disabled = update(x.shortChannelId, 0, {
			timestamp: later,
			disabled: true
		});
		expect(graph.wouldAcceptChannelUpdate(disabled)).to.equal(true);
		expect(graph.applyChannelUpdate(disabled, { verified: true })).to.equal(
			true
		);
	});

	it('forgets a spent channel 72 blocks after the spend, and reports it', () => {
		const { graph, evicted, x } = world();
		graph.markChannelFundingSpent(x.shortChannelId, 990);
		expect(
			graph.forgetSpentChannels(990 + SPENT_CHANNEL_FORGET_DEPTH - 1)
		).to.equal(0);
		expect(graph.getChannel(x.shortChannelId)).to.not.equal(undefined);

		expect(
			graph.forgetSpentChannels(990 + SPENT_CHANNEL_FORGET_DEPTH)
		).to.equal(1);
		expect(graph.getChannel(x.shortChannelId)).to.equal(undefined);
		expect(evicted).to.deep.equal([x.shortChannelId.toString('hex')]);
	});

	it('a spliced channel is usable again once its new announcement arrives', () => {
		const { graph, evicted, x } = world();
		graph.markChannelFundingSpent(x.shortChannelId, 990);

		// The splice's SCID names the block that spent the old output.
		const splice = addChannel(graph, scidAt(990, 3), B, C);
		expect(graph.getChannel(x.shortChannelId)).to.equal(undefined);
		expect(evicted).to.deep.equal([x.shortChannelId.toString('hex')]);
		expect(route(graph)[1]).to.equal(splice.shortChannelId.toString('hex'));

		// Learned the other way round, the old entry goes when it is marked.
		const other = world();
		const early = addChannel(other.graph, scidAt(990, 3), B, C);
		other.graph.markChannelFundingSpent(other.x.shortChannelId, 990);
		expect(other.graph.getChannel(other.x.shortChannelId)).to.equal(undefined);
		expect(route(other.graph)[1]).to.equal(
			early.shortChannelId.toString('hex')
		);
	});

	it('a channel between the same nodes from another block replaces nothing', () => {
		const { graph, x } = world();
		graph.markChannelFundingSpent(x.shortChannelId, 990);
		addChannel(graph, scidAt(991), B, C);
		expect(graph.getChannel(x.shortChannelId)!.fundingSpentHeight).to.equal(
			990
		);
	});

	it('the spent height survives a stored row, and drops its funding proof', () => {
		const { graph, x } = world();
		graph.markChannelFundingProven(x.shortChannelId);
		graph.markChannelFundingSpent(x.shortChannelId, 990);
		const row = deserializeGraphChannel(
			serializeGraphChannel(graph.getChannel(x.shortChannelId)!)
		);
		expect(row.fundingSpentHeight).to.equal(990);
		expect(row.fundingVerified).to.equal(undefined);

		const restored = new NetworkGraph(REGTEST_CHAIN_HASH);
		restored.restoreChannel({ ...row, fundingVerified: true });
		const channel = restored.getChannel(x.shortChannelId)!;
		expect(channel.fundingSpentHeight).to.equal(990);
		expect(channel.fundingVerified).to.equal(undefined);
		expect(
			restored.forgetSpentChannels(990 + SPENT_CHANNEL_FORGET_DEPTH)
		).to.equal(1);

		const junk = new NetworkGraph(REGTEST_CHAIN_HASH);
		junk.restoreChannel({
			...row,
			fundingSpentHeight: 'soon' as unknown as number
		} as IGraphChannel);
		expect(junk.getChannel(x.shortChannelId)!.fundingSpentHeight).to.equal(
			undefined
		);
	});
});

describe('findAnnouncedChannelSpend (issue #2048)', () => {
	const ann = announcement(scidAt(500), pubkey('b'), pubkey('c'));

	it('finds the confirmed spend and its height', async () => {
		const chain = new FakeChain();
		chain.fund(ann);
		const backend = chain.backend();
		expect((await findAnnouncedChannelSpend(backend, ann)).verdict).to.equal(
			'unspent'
		);

		chain.spend(ann, 990);
		const spend = await findAnnouncedChannelSpend(backend, ann);
		expect(spend).to.deep.include({ verdict: 'spent', height: 990 });
		expect(spend.lookups).to.be.at.most(MAX_FUNDING_SPEND_LOOKUPS);
		expect(chain.lookups).to.equal(2 + spend.lookups);
	});

	it('a payment to the script that spends nothing proves no spend', async () => {
		const chain = new FakeChain();
		chain.fund(ann);
		chain.spend(ann, 980, { unrelated: true });
		// Still unspent: the unrelated payment leaves the funding output alone.
		expect(
			(await findAnnouncedChannelSpend(chain.backend(), ann)).verdict
		).to.equal('unspent');
	});

	it('payments to the script before the close do not hide it', async () => {
		const chain = new FakeChain();
		chain.fund(ann);
		chain.spend(ann, 600, { unrelated: true });
		chain.spend(ann, 700, { unrelated: true });
		chain.spend(ann, 990);
		const spend = await findAnnouncedChannelSpend(chain.backend(), ann);
		expect(spend).to.deep.include({ verdict: 'spent', height: 990 });
		expect(spend.lookups).to.be.at.most(MAX_FUNDING_SPEND_LOOKUPS);
	});

	it('settles nothing for a fabricated SCID or a down backend', async () => {
		const chain = new FakeChain();
		expect(
			(await findAnnouncedChannelSpend(chain.backend(), ann)).verdict
		).to.equal('unknown');
		const down: IChainBackend = {
			...chain.backend(),
			getScriptHashHistory: async (): Promise<[]> => {
				throw new Error('Electrum not connected');
			}
		};
		expect((await findAnnouncedChannelSpend(down, ann)).verdict).to.equal(
			'unavailable'
		);
	});
});

describe('Spend checks from payments (issue #2048)', () => {
	function seed(id: number, label: string): Buffer {
		return crypto
			.createHash('sha256')
			.update(`graph-spend-${id}-${label}`)
			.digest();
	}

	function makeConfig(id: number): INodeConfig {
		const keys = [0, 1, 2, 3, 4].map((i) => seed(id, `k${i}`));
		return {
			nodePrivateKey: seed(id, 'node'),
			network: Network.REGTEST,
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
			channelBasepoints: {
				fundingPubkey: getPublicKey(keys[0]),
				revocationBasepoint: getPublicKey(keys[1]),
				paymentBasepoint: getPublicKey(keys[2]),
				delayedPaymentBasepoint: getPublicKey(keys[3]),
				htlcBasepoint: getPublicKey(keys[4]),
				firstPerCommitmentPoint: Buffer.alloc(33)
			},
			perCommitmentSeed: seed(id, 'per-commitment'),
			fundingPrivkey: keys[0],
			htlcBasepointSecret: keys[4]
		};
	}

	let alice: LightningNode;
	let bob: LightningNode;

	beforeEach(() => {
		alice = new LightningNode(makeConfig(1));
		bob = new LightningNode(makeConfig(2));
		for (const n of [alice, bob]) n.on('node:error', () => {});
		alice.on('message:outbound', (peer, type, payload) => {
			if (peer === bob.getNodeId()) {
				bob.handlePeerMessage(alice.getNodeId(), type, payload);
			}
		});
		bob.on('message:outbound', (peer, type, payload) => {
			if (peer === alice.getNodeId()) {
				alice.handlePeerMessage(bob.getNodeId(), type, payload);
			}
		});
		const pending = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			pending,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
	});

	afterEach(() => {
		alice.destroy();
		bob.destroy();
	});

	const graphOf = (n: LightningNode): NetworkGraph =>
		(n as unknown as { graph: NetworkGraph }).graph;
	const setBackend = (n: LightningNode, backend: IChainBackend): void => {
		(n as unknown as { _chainBackend: IChainBackend })._chainBackend = backend;
	};
	const settle = async (n: LightningNode): Promise<void> => {
		const internals = n as unknown as {
			graphSpendChecking: boolean;
			gossipFundingChecking: boolean;
		};
		for (
			let i = 0;
			i < 200 &&
			(i === 0 ||
				internals.graphSpendChecking ||
				internals.gossipFundingChecking);
			i++
		) {
			await new Promise<void>((resolve) => setImmediate(resolve));
		}
		expect(internals.graphSpendChecking).to.equal(false);
		expect(internals.gossipFundingChecking).to.equal(false);
	};

	it('a closed third-party channel fails one payment, and the next routes around it', async () => {
		const B = Buffer.from(bob.getNodeId(), 'hex');
		const C = pubkey('carol');
		const D = pubkey('dave');
		const graph = graphOf(alice);
		const x = addChannel(graph, scidAt(500), B, C);
		const y = addChannel(graph, scidAt(501), B, D);
		const z = addChannel(graph, scidAt(502), D, C);
		const chain = new FakeChain();
		for (const ann of [x, y, z]) chain.fund(ann);
		// X closed ten blocks ago; Bob no longer has it.
		chain.spend(x, 990);
		setBackend(alice, chain.backend());
		const logs: IStructuredLog[] = [];
		alice.on('log', (log: IStructuredLog) => logs.push(log));

		const first = alice.sendKeysend({ destination: C, amountMsat: 10_000n });
		expect(
			first.route!.hops[1].shortChannelId.equals(x.shortChannelId)
		).to.equal(true);
		await settle(alice);
		const failed = alice.getPayment(first.paymentHash)!;
		expect(failed.status).to.equal(PaymentStatus.FAILED);
		expect(failed.failureCode).to.equal(UNKNOWN_NEXT_PEER);
		expect(
			logs.some(
				(l) =>
					l.action === 'graph_funding_check' &&
					l.data.shortChannelId === x.shortChannelId.toString('hex') &&
					l.data.verdict === 'spent'
			)
		).to.equal(true);
		expect(graph.getChannel(x.shortChannelId)!.fundingSpentHeight).to.equal(
			990
		);

		// Mission control is not what steers the next payment.
		(alice as unknown as { missionControl: MissionControl }).missionControl =
			new MissionControl();
		const second = alice.sendKeysend({ destination: C, amountMsat: 10_000n });
		expect(
			second.route!.hops[1].shortChannelId.equals(y.shortChannelId)
		).to.equal(true);
		await settle(alice);

		const checks = logs.filter((l) => l.action === 'graph_funding_check');
		expect(checks.length).to.be.greaterThan(0);
		for (const check of checks) {
			expect(check.data.lookups as number).to.be.at.most(
				MAX_FUNDING_SPEND_LOOKUPS
			);
			expect(check.data.paymentHash).to.be.a('string');
		}
		const perPayment = new Map<string, number>();
		for (const check of checks) {
			const hash = check.data.paymentHash as string;
			perPayment.set(hash, (perPayment.get(hash) ?? 0) + 1);
		}
		for (const count of perPayment.values()) {
			expect(count).to.be.at.most(
				(LightningNode as unknown as { GRAPH_SPEND_CHECKS_PER_ROUTE: number })
					.GRAPH_SPEND_CHECKS_PER_ROUTE + 1
			);
		}
		expect(chain.lookups).to.equal(
			checks.reduce((sum, c) => sum + (c.data.lookups as number), 0)
		);

		// Checked and unspent, Y and Z are not checked again when the next
		// route is chosen. Bob has no Y either, so only that failure asks.
		const seen = logs.length;
		const third = alice.sendKeysend({ destination: C, amountMsat: 10_000n });
		await settle(alice);
		const thirdChecks = logs
			.slice(seen)
			.filter((l) => l.action === 'graph_funding_check');
		expect(
			thirdChecks.map((l) => [l.data.reason, l.data.shortChannelId])
		).to.deep.equal([['failure', y.shortChannelId.toString('hex')]]);
		expect(thirdChecks[0].data.paymentHash).to.equal(
			third.paymentHash.toString('hex')
		);

		// BOLT 7: forgotten 72 blocks after the spend.
		alice.handleNewBlock(990 + SPENT_CHANNEL_FORGET_DEPTH);
		expect(graph.getChannel(x.shortChannelId)).to.equal(undefined);
	});

	it('admits a recently spent announcement as spent instead of refusing it', async () => {
		const B = Buffer.from(bob.getNodeId(), 'hex');
		const chain = new FakeChain();
		const recent = announcement(scidAt(600), B, pubkey('erin'));
		const old = announcement(scidAt(601), B, pubkey('frank'));
		chain.fund(recent);
		chain.fund(old);
		chain.spend(recent, 990);
		chain.spend(old, 1000 - SPENT_CHANNEL_FORGET_DEPTH);
		setBackend(alice, chain.backend());

		const graph = graphOf(alice);
		graph.addChannelAnnouncement(recent, { verified: true });
		graph.addChannelAnnouncement(old, { verified: true });
		await settle(alice);

		expect(
			graph.getChannel(recent.shortChannelId)!.fundingSpentHeight
		).to.equal(990);
		expect(graph.getChannel(old.shortChannelId)).to.equal(undefined);
	});
});
