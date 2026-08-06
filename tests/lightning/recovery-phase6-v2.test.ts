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
 * 2. QUORUM DOES NOT OPEN V2 CHANNELS AT ALL. Barrier-gating the messages
 *    does not make the state behind them durable: the interactive-funding
 *    session is process-local and is discarded on disconnect, while BOLT 2
 *    requires retaining the funding transaction and resuming the signature
 *    exchange through channel_reestablish.next_funding. Quorum's promise is
 *    that a peer which has seen new channel state can be resumed to, so
 *    rather than weaken the promise for one channel type, the mode refuses
 *    to START v2 opens. Established channels, including ones originally
 *    opened with v2, are untouched.
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

describe('Recovery phase 6: quorum does not start dual-funded opens', function () {
	this.timeout(20_000);

	/** An enforcing barrier. Nothing here ever has to be RELEASED: every
	 *  assertion is about a refusal that happens before a message exists. */
	function quorumRecovery(): INodeConfig['recovery'] {
		// A replication stub, deliberately. Every assertion below is about a
		// refusal that happens before any message exists, so nothing here is
		// ever released, replicated or waited on; standing up real guardians
		// would only make the tests slower without making them stricter. The
		// three reads the barrier actually performs are answered honestly:
		// nothing replicated, no lost backfill, no stale watermark.
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

	it('masks option_dual_fund so a compliant peer never proposes one', function () {
		const storage = openStorage();
		const node = quorumNode(10, storage);
		expect(
			localFeaturesOf(node).hasFeature(Feature.DUAL_FUND),
			'the bit we advertise'
		).to.equal(false);
		// Which is also what the generic openChannel routes by, so it picks v1
		// rather than a v2 this node would then refuse itself.
		expect(node.peerFundingInfo('02'.repeat(33)).dualFund).to.equal(false);
		node.destroy();
		storage.close();
	});

	it('refuses an outbound v2 open before it allocates anything', function () {
		const storage = openStorage();
		const node = quorumNode(12, storage);
		const manager = managerOf(node);
		const indexBefore = manager.nextChannelIndex;
		const peer = '02'.repeat(33);

		expect(() =>
			node.openChannelV2(peer, {
				fundingSatoshis: 150_000n,
				fundingFeeratePerkw: 1000
			})
		).to.throw(/dual-funded/);

		// The manager primitive is published, so an embedder driving the
		// negotiation itself answers to the same rule.
		expect(() =>
			manager.createDualFundedChannel(peer, {
				fundingSatoshis: 150_000n,
				fundingFeeratePerkw: 1000
			} as unknown as Parameters<typeof manager.createDualFundedChannel>[1])
		).to.throw(/dual-funded/);

		// Before ANY side effect: no channel, no temp channel, and no burnt
		// per-channel key index. The index is the assertion that pins the
		// guard ahead of deriveKeysForNewChannel rather than behind it.
		expect(manager.listChannels()).to.have.length(0);
		expect(manager.nextChannelIndex).to.equal(indexBefore);
		expect(storage.loadAllChannels()).to.have.length(0);

		node.destroy();
		storage.close();
	});

	it('refuses an inbound open_channel2 and leaves no debris', function () {
		const storage = openStorage();
		const node = quorumNode(14, storage);
		const manager = managerOf(node);
		const indexBefore = manager.nextChannelIndex;
		const errors: string[] = [];
		manager.on('error', (_id: Buffer | null, message: string) => {
			errors.push(message);
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

		expect(errors.join(' ')).to.contain('dual-funded');
		expect(manager.listChannels()).to.have.length(0);
		expect(manager.nextChannelIndex).to.equal(indexBefore);
		expect(storage.loadAllChannels()).to.have.length(0);

		node.destroy();
		storage.close();
	});

	it('refuses to come up over a v2 open that is already in progress', function () {
		const storage = openStorage();
		// A session begun under async-remote, sitting in the state the
		// operator is about to switch quorum on over. It may already have
		// crossed commitment_signed, so it is neither resumable nor safe to
		// discard on our own account.
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
		storage.saveChannel(
			inFlight.channelId.toString('hex'),
			inFlight,
			'02'.repeat(33)
		);

		expect(
			() =>
				new LightningNode(
					makeNodeConfig(17, {
						storage,
						recovery: quorumRecovery()
					})
				)
		).to.throw(/dual-funded open is in progress/);

		// And the same database comes up fine in async-remote, which is where
		// the operator finishes or abandons it.
		const asyncNode = new LightningNode(
			makeNodeConfig(17, { storage, recovery: { enabled: true } })
		);
		asyncNode.on('node:error', () => {});
		expect(asyncNode.getChannelManager().listChannels()).to.have.length(1);
		asyncNode.destroy();
		storage.close();
	});

	it('still refuses to come up over a RESUMABLE (recorded) v2 open', function () {
		const storage = openStorage();
		// A row carrying the durable v2InFlight record: restoreChannel marks
		// it for reestablish before the guard runs, so the guard must look
		// through AWAITING_REESTABLISH to keep seeing the in-flight open.
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
		storage.saveChannel(
			inFlight.channelId.toString('hex'),
			inFlight,
			'02'.repeat(33)
		);

		expect(
			() =>
				new LightningNode(
					makeNodeConfig(19, {
						storage,
						recovery: quorumRecovery()
					})
				)
		).to.throw(/dual-funded open is in progress/);

		// Async-remote resumes it instead of refusing: the record marks the
		// row for reestablish on restore.
		const asyncNode = new LightningNode(
			makeNodeConfig(19, { storage, recovery: { enabled: true } })
		);
		asyncNode.on('node:error', () => {});
		const restored = asyncNode.getChannelManager().listChannels();
		expect(restored).to.have.length(1);
		expect(restored[0].getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		asyncNode.destroy();
		storage.close();
	});

	it('leaves an established v2 channel alone', function () {
		const storage = openStorage();
		// Originally opened with v2, long since an ordinary channel: quorum
		// restricts STARTING interactive opens, not operating what they built.
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
