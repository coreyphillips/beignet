/**
 * Recovery Protocol phase 6: dual-funded (v2) opens.
 *
 * Two separate things, both about the same window: the interactive-tx round
 * that ends in the first v2 commitment_signed.
 *
 * 1. PERSIST-BEFORE-SEND HAS TO ACTUALLY RESOLVE THE CHANNEL. A v2 channel
 *    derives its permanent channel_id during accept_channel2 but stays
 *    registered under its TEMPORARY id until the open leaves
 *    AWAITING_TX_SIGNATURES, because a mid-round disconnect is aborted by
 *    the temp-map sweep. The persist event carried the permanent id into a
 *    listener that resolved ids through the permanent map, so it found
 *    nothing, returned, and the batch dispatched anyway: commitment_signed
 *    left with no state on disk behind it, and under a quorum barrier the
 *    frame it should have waited on never existed.
 *
 * 2. QUORUM OPENS V2 CHANNELS BEHIND THE BARRIER. The interactive-funding
 *    round is durable now: the v2InFlight record rides channel_state
 *    mutations into the journal and guardian frames, and BOLT 2 resumption
 *    over channel_reestablish.next_funding works across restarts and
 *    guardian-only restores. So the phase 6 refusal that once covered the
 *    gap is gone. What quorum still adds is the wire gate: the first
 *    commitment_signed and tx_signatures are barrier-class messages, so
 *    they wait on replication like every other irreversible send, and a
 *    restored in-flight open comes up resumable instead of being refused.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);

import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, IFundingProvider } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { ISpliceWalletInput } from '../../src/lightning/channel/channel';
import { MessageType } from '../../src/lightning/message/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	DurabilityBarrier,
	GuardianReplicator,
	RecoveryManager
} from '../../src/lightning/recovery';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { encodeOpenChannel2Message } from '../../src/lightning/message/dual-funding';
import { createOpenerState } from '../../src/lightning/channel/channel-state';

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`p6-v2-seed-${id}`).digest();
}

function makeBasepoints(seedId: number): {
	basepoints: IChannelBasepoints;
	fundingPrivkey: Buffer;
	htlcSecret: Buffer;
} {
	const seed = makeSeed(seedId);
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(keys[0]),
			revocationBasepoint: getPublicKey(keys[1]),
			paymentBasepoint: getPublicKey(keys[2]),
			delayedPaymentBasepoint: getPublicKey(keys[3]),
			htlcBasepoint: getPublicKey(keys[4]),
			firstPerCommitmentPoint: perCommitmentPointFromSecret(
				generateFromSeed(makeSeed(seedId + 100), MAX_INDEX)
			)
		},
		fundingPrivkey: keys[0],
		htlcSecret: keys[4]
	};
}

function makeNodeConfig(
	seedId: number,
	opts: {
		storage?: SqliteStorage;
		recovery?: INodeConfig['recovery'];
		fundingProvider?: IFundingProvider;
	} = {}
): INodeConfig {
	const seed = makeSeed(seedId);
	const { basepoints, fundingPrivkey, htlcSecret } = makeBasepoints(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: basepoints,
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		htlcBasepointSecret: htlcSecret,
		...opts
	};
}

/** A real spendable P2WPKH UTXO with a working witness-signing closure. */
function makeWalletInput(valueSats: number): ISpliceWalletInput {
	const priv = crypto.randomBytes(32);
	const pub = getPublicKey(priv);
	const payment = bitcoin.payments.p2wpkh({ pubkey: pub });
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(crypto.randomBytes(32), 0);
	prevTx.addOutput(payment.output!, valueSats);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output!;
	return {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: BigInt(valueSats),
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value): Buffer[] => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [
				bitcoin.script.signature.encode(
					Buffer.from(ecc.sign(sighash, priv)),
					bitcoin.Transaction.SIGHASH_ALL
				),
				pub
			];
		}
	};
}

function fundingProviderWith(input: ISpliceWalletInput): IFundingProvider {
	const changeScript = bitcoin.payments.p2wpkh({
		hash: crypto.randomBytes(20)
	}).output!;
	return {
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a v2 open');
		},
		broadcastTransaction: async () => 'unused',
		selectSpliceInputs: async () => ({ inputs: [input], changeScript }),
		selectMaxDualFundingInputs: async () => ({
			inputs: [input],
			changeScript
		})
	};
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId()) {
			b.handlePeerMessage(a.getNodeId(), type, payload);
		}
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId()) {
			a.handlePeerMessage(b.getNodeId(), type, payload);
		}
	});
}

async function settle(pred: () => boolean, ms = 3000): Promise<void> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (pred()) return;
		await new Promise((resolve) => setImmediate(resolve));
	}
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

const recoveryOf = (node: LightningNode): RecoveryManager =>
	(node as unknown as { recovery: RecoveryManager }).recovery;

/** The init feature vector this node advertises. */
const localFeaturesOf = (node: LightningNode): FeatureFlags =>
	(node as unknown as { localFeatures: FeatureFlags }).localFeatures;

describe('Recovery phase 6: the v2 opening round persists what it sends', function () {
	this.timeout(20_000);

	it('the first v2 commitment_signed reaches disk before it reaches the peer', async function () {
		const storage = openStorage();
		const opener = new LightningNode(
			makeNodeConfig(1, {
				storage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(2));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		connectNodes(opener, acceptor);

		// What was on disk at the INSTANT each commitment_signed left, rather
		// than at the end of the flow: the channel is still in the temp map
		// here, keyed by its TEMPORARY id, while the batch persists under the
		// PERMANENT one, and a persist that resolved nothing used to let the
		// message go out anyway.
		// eslint-disable-next-line prefer-const
		let openerChannel: { getChannelId(): Buffer | null } | undefined;
		const rowsAtSend: string[][] = [];
		const outboxAtSend: number[][] = [];
		opener.on('message:outbound', (_peer: string, type: number) => {
			if (type !== MessageType.COMMITMENT_SIGNED) return;
			rowsAtSend.push(storage.loadAllChannels().map((row) => row.channelId));
			const idHex = openerChannel?.getChannelId()?.toString('hex');
			outboxAtSend.push(
				idHex
					? recoveryOf(opener)
							.getOutbox(idHex)
							.map((row) => row.messageType)
					: []
			);
		});

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		openerChannel = channel;
		await settle(
			() => channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(
			channel.getState(),
			'the negotiation completed, so the commitment round happened'
		).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);

		const permanentId = channel.getChannelId()!.toString('hex');
		const temporaryId = channel.getTemporaryChannelId().toString('hex');
		expect(permanentId, 'the permanent id is derived by now').to.not.equal(
			temporaryId
		);

		expect(rowsAtSend.length, 'commitment_signed was sent').to.be.greaterThan(
			0
		);
		expect(
			rowsAtSend[0],
			'the state justifying it was already on disk, under the permanent id'
		).to.include(permanentId);

		// The decisive one: the bytes were in the outbox against that same id
		// BEFORE they went out, so the commit that authorized this message is
		// the commit that recorded it, and a restart retransmits exactly what
		// the peer was given.
		expect(
			outboxAtSend[0],
			'the wire bytes were committed before they were sent'
		).to.include(MessageType.COMMITMENT_SIGNED);

		opener.destroy();
		acceptor.destroy();
		storage.close();
	});

	it('a persist that does not commit withholds the v2 commitment_signed', async function () {
		const storage = openStorage();
		const opener = new LightningNode(
			makeNodeConfig(3, {
				storage,
				recovery: { enabled: true },
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(4));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		connectNodes(opener, acceptor);

		// The disk refuses exactly when the v2 commitment round asks. Before,
		// an unresolved channel id produced the same non-commit silently, and
		// the message went out regardless; the request now answers for itself.
		const recovery = recoveryOf(opener) as unknown as {
			commit: (...a: unknown[]) => unknown;
		};
		const realCommit = recovery.commit.bind(recovery);
		let refuseFrom = false;
		recovery.commit = (...args: unknown[]): unknown =>
			refuseFrom
				? {
						committed: false,
						released: [],
						frameSequence: null,
						error: new Error('disk full')
				  }
				: realCommit(...args);

		const sent: number[] = [];
		opener.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		refuseFrom = true;
		await settle(() => sent.includes(MessageType.TX_COMPLETE), 1500);

		expect(
			sent.includes(MessageType.COMMITMENT_SIGNED),
			'no commitment_signed behind a persist that rolled back'
		).to.equal(false);
		expect(channel.getState()).to.not.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		opener.destroy();
		acceptor.destroy();
		storage.close();
	});

	it('a node without storage is unchanged: nothing to commit, nothing withheld', async function () {
		const opener = new LightningNode(
			makeNodeConfig(5, {
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		const acceptor = new LightningNode(makeNodeConfig(6));
		opener.on('node:error', () => {});
		acceptor.on('node:error', () => {});
		connectNodes(opener, acceptor);

		const channel = opener.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		await settle(
			() => channel.getState() === ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(channel.getState()).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		opener.destroy();
		acceptor.destroy();
	});

	it('async-remote keeps advertising option_dual_fund', function () {
		const storage = openStorage();
		const node = new LightningNode(
			makeNodeConfig(7, { storage, recovery: { enabled: true } })
		);
		node.on('node:error', () => {});
		expect(localFeaturesOf(node).hasFeature(Feature.DUAL_FUND)).to.equal(true);
		node.destroy();
		storage.close();
	});
});

/** Reachable through the manager as well as the node wrapper. */
const managerOf = (node: LightningNode): ChannelManager =>
	(node as unknown as { channelManager: ChannelManager }).channelManager;

describe('Recovery phase 6: quorum opens dual-funded channels behind the barrier', function () {
	this.timeout(20_000);

	/** An enforcing barrier. Nothing here is ever RELEASED: the stub never
	 *  confirms replication, so the barrier HOLDS what it gates, and every
	 *  assertion is about a hold or a startup disposition. */
	function quorumRecovery(): INodeConfig['recovery'] {
		// A replication stub, deliberately. The assertions below are about
		// the open STARTING and its irreversible sends being held, never
		// about a release, so standing up real guardians would only make the
		// tests slower without making them stricter. The three reads the
		// barrier actually performs are answered honestly: nothing
		// replicated, no lost backfill, no stale watermark.
		const replicator = {
			replicatedThrough: (): bigint => 0n,
			namespaceLostBackfill: (): string | null => null,
			watermarkExceedingJournal: (): string | null => null,
			replicatePending: async (): Promise<void> => undefined
		} as unknown as GuardianReplicator;
		return {
			enabled: true,
			durability: 'quorum',
			barrier: new DurabilityBarrier({
				durability: 'quorum',
				replicator,
				lease: () => null,
				timeoutMs: 500,
				retryDelayMs: 50
			})
		};
	}

	function quorumNode(seedId: number, storage: SqliteStorage): LightningNode {
		const node = new LightningNode(
			makeNodeConfig(seedId, {
				storage,
				recovery: quorumRecovery(),
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			})
		);
		node.on('node:error', () => {});
		node.on('error', () => {});
		return node;
	}

	it('advertises option_dual_fund like every other mode', function () {
		const storage = openStorage();
		const node = quorumNode(10, storage);
		// The durable v2InFlight record made the round resumable, so quorum
		// no longer masks the bit: a compliant peer may propose a v2 open,
		// and the generic openChannel routes by this same bit, so it picks
		// v2 against a capable peer just as it would in async-remote.
		expect(
			localFeaturesOf(node).hasFeature(Feature.DUAL_FUND),
			'the bit we advertise'
		).to.equal(true);
		node.destroy();
		storage.close();
	});

	it('starts an outbound v2 open and holds its commitment_signed behind the barrier', async function () {
		const storage = openStorage();
		const node = quorumNode(12, storage);
		const acceptor = new LightningNode(makeNodeConfig(13));
		acceptor.on('node:error', () => {});
		connectNodes(node, acceptor);

		const sent: number[] = [];
		node.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});

		// No refusal: the round is durable, so quorum starts the open and
		// lets the barrier gate the irreversible sends instead.
		const channel = node.openChannelV2(acceptor.getNodeId(), {
			fundingSatoshis: 150_000n,
			fundingFeeratePerkw: 1000
		});
		// The commitment round persists BEFORE it sends, so the durable row
		// is the sign the negotiation reached the commitment boundary.
		await settle(() => storage.loadAllChannels().length > 0, 2000);

		expect(sent, 'the open went out').to.include(MessageType.OPEN_CHANNEL2);
		expect(sent, 'negotiation ran to the commitment boundary').to.include(
			MessageType.TX_COMPLETE
		);
		expect(
			storage.loadAllChannels().length,
			'the commitment persist landed'
		).to.be.greaterThan(0);
		// The stub replicator never confirms replication, so the barrier is
		// what stands between the negotiated round and the wire now: the
		// commitment_signed is HELD, not refused up front.
		expect(sent).to.not.include(MessageType.COMMITMENT_SIGNED);
		expect(channel.getState()).to.not.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		node.destroy();
		acceptor.destroy();
		storage.close();
	});

	it('accepts an inbound open_channel2 and negotiates', async function () {
		const storage = openStorage();
		const node = quorumNode(14, storage);
		const manager = managerOf(node);
		const errors: string[] = [];
		manager.on('error', (_id: Buffer | null, message: string) => {
			errors.push(message);
		});
		const sent: number[] = [];
		node.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});

		const peerSide = makeBasepoints(15);
		const openMsg = encodeOpenChannel2Message({
			chainHash: REGTEST_CHAIN_HASH,
			channelId: crypto.randomBytes(32),
			fundingFeeratePerkw: 1000,
			commitmentFeeratePerkw: 253,
			fundingSatoshis: 150_000n,
			dustLimitSatoshis: 546n,
			maxHtlcValueInFlightMsat: 500_000_000n,
			htlcMinimumMsat: 1n,
			toSelfDelay: 144,
			maxAcceptedHtlcs: 483,
			locktime: 0,
			fundingPubkey: peerSide.basepoints.fundingPubkey,
			revocationBasepoint: peerSide.basepoints.revocationBasepoint,
			paymentBasepoint: peerSide.basepoints.paymentBasepoint,
			delayedPaymentBasepoint: peerSide.basepoints.delayedPaymentBasepoint,
			htlcBasepoint: peerSide.basepoints.htlcBasepoint,
			firstPerCommitmentPoint: peerSide.basepoints.firstPerCommitmentPoint,
			secondPerCommitmentPoint: peerSide.basepoints.firstPerCommitmentPoint,
			channelFlags: 1
		});
		manager.handleMessage('02'.repeat(33), MessageType.OPEN_CHANNEL2, openMsg);
		await settle(() => sent.includes(MessageType.ACCEPT_CHANNEL2), 1500);

		// Answered, not refused.
		expect(errors.join(' ')).to.not.contain('dual-funded');
		expect(sent, 'the open was answered').to.include(
			MessageType.ACCEPT_CHANNEL2
		);

		node.destroy();
		storage.close();
	});

	it('comes up over a legacy record-less v2 open, the same inert orphan async-remote keeps', function () {
		const storage = openStorage();
		// A row WITHOUT the durable v2InFlight record: nothing to resume
		// from, but nothing to refuse over either. Quorum now restores it
		// exactly as async-remote does, an inert orphan for the operator to
		// finish or abandon.
		const inFlight = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(16).basepoints,
			localPerCommitmentSeed: makeSeed(16)
		});
		inFlight.channelId = crypto.randomBytes(32);
		inFlight.state = ChannelState.AWAITING_TX_SIGNATURES;
		// Two identically seeded databases: destroy() closes the storage it
		// was handed, and an in-memory database does not survive that.
		const quorumStorage = storage;
		const asyncStorage = openStorage();
		for (const s of [quorumStorage, asyncStorage]) {
			s.saveChannel(
				inFlight.channelId.toString('hex'),
				inFlight,
				'02'.repeat(33)
			);
		}

		const quorumRestored = new LightningNode(
			makeNodeConfig(17, {
				storage: quorumStorage,
				recovery: quorumRecovery()
			})
		);
		quorumRestored.on('node:error', () => {});
		const restored = quorumRestored.getChannelManager().listChannels();
		expect(restored).to.have.length(1);
		expect(restored[0].getState()).to.equal(
			ChannelState.AWAITING_TX_SIGNATURES
		);
		quorumRestored.destroy();

		// And the same database shape comes up the same way in async-remote.
		const asyncNode = new LightningNode(
			makeNodeConfig(17, { storage: asyncStorage, recovery: { enabled: true } })
		);
		asyncNode.on('node:error', () => {});
		expect(asyncNode.getChannelManager().listChannels()).to.have.length(1);
		asyncNode.destroy();
	});

	it('comes up RESUMABLE over a recorded v2 open', function () {
		const storage = openStorage();
		// A row carrying the durable v2InFlight record: restoreChannel marks
		// it for reestablish, and quorum lets it come up that way, because
		// the record is exactly what makes the round provable again.
		const inFlight = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(19).basepoints,
			localPerCommitmentSeed: makeSeed(19)
		});
		inFlight.channelId = crypto.randomBytes(32);
		inFlight.state = ChannelState.AWAITING_TX_SIGNATURES;
		inFlight.fundingVersion = 2;
		const fundingTx = new bitcoin.Transaction();
		fundingTx.version = 2;
		fundingTx.addInput(crypto.randomBytes(32), 0);
		fundingTx.addOutput(
			Buffer.concat([Buffer.from([0x00, 0x20]), crypto.randomBytes(32)]),
			150_000
		);
		inFlight.v2InFlight = {
			fundingTxid: Buffer.from(fundingTx.getHash()),
			fundingOutputIndex: 0,
			fundingTxHex: fundingTx.toHex(),
			fullySigned: false,
			isInitiator: true,
			localContributionSats: 150_000n,
			remoteContributionSats: 0n,
			fundingFeeratePerkw: 1000,
			weSignFirst: false,
			ourWitnesses: [],
			ourWalletInputIndices: [],
			inputPrevouts: [],
			remoteCommitmentSig: null,
			sentTxSignatures: false,
			receivedTxSignatures: false,
			confirmed: false,
			rbfAttempt: 0
		};
		// Two identically seeded databases: destroy() closes the storage it
		// was handed, and an in-memory database does not survive that.
		const quorumStorage = storage;
		const asyncStorage = openStorage();
		for (const s of [quorumStorage, asyncStorage]) {
			s.saveChannel(
				inFlight.channelId.toString('hex'),
				inFlight,
				'02'.repeat(33)
			);
		}

		const quorumRestored = new LightningNode(
			makeNodeConfig(19, {
				storage: quorumStorage,
				recovery: quorumRecovery()
			})
		);
		quorumRestored.on('node:error', () => {});
		const restored = quorumRestored.getChannelManager().listChannels();
		expect(restored).to.have.length(1);
		expect(restored[0].getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		quorumRestored.destroy();

		// Async-remote resumes it the same way: the record marks the row for
		// reestablish on restore in either mode.
		const asyncNode = new LightningNode(
			makeNodeConfig(19, { storage: asyncStorage, recovery: { enabled: true } })
		);
		asyncNode.on('node:error', () => {});
		const restoredAsync = asyncNode.getChannelManager().listChannels();
		expect(restoredAsync).to.have.length(1);
		expect(restoredAsync[0].getState()).to.equal(
			ChannelState.AWAITING_REESTABLISH
		);
		asyncNode.destroy();
	});

	it('leaves an established v2 channel alone', function () {
		const storage = openStorage();
		// Originally opened with v2, long since an ordinary channel: under
		// quorum it restores and operates like any other channel.
		const established = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(18).basepoints,
			localPerCommitmentSeed: makeSeed(18)
		});
		established.channelId = crypto.randomBytes(32);
		established.state = ChannelState.NORMAL;
		storage.saveChannel(
			established.channelId.toString('hex'),
			established,
			'02'.repeat(33)
		);

		const node = quorumNode(19, storage);
		expect(node.getChannelManager().listChannels()).to.have.length(1);
		// Restored and operable: AWAITING_REESTABLISH is the ordinary
		// post-restart disposition of a NORMAL channel, not a refusal.
		expect(
			node.getChannelManager().getChannel(established.channelId)!.getState()
		).to.equal(ChannelState.AWAITING_REESTABLISH);
		node.destroy();
		storage.close();
	});
});

export { makeNodeConfig, makeWalletInput, fundingProviderWith, connectNodes };
export { settle, openStorage, managerOf, recoveryOf };
