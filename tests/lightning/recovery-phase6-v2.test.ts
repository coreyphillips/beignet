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
 *    they wait on replication like every other irreversible send. A
 *    RECORDED in-flight open comes up resumable instead of being refused;
 *    a legacy record-less row, which cannot actually resume, still
 *    refuses startup, and quorum + preferTaproot still masks the bit
 *    because taproot v2 signing does not exist.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
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
import { deriveV2TemporaryChannelId } from '../../src/lightning/channel/validation';
import { MessageType } from '../../src/lightning/message/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	CRASH_V1_PROFILE,
	DurabilityBarrier,
	GuardianClient,
	GuardianHttpServer,
	GuardianReplicator,
	IBoundGuardianClient,
	IWriterLeaseKeys,
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	ReferenceGuardian,
	RestoreDriver,
	computeGuardianSetId,
	deriveRecoveryRoot,
	loadWriterLease,
	reconstructFromFrames,
	xOnlyFromSecret
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

	it('quorum with preferTaproot keeps the bit masked: taproot v2 signing does not exist', function () {
		const storage = openStorage();
		// The generic openChannel routes by this bit; advertising it under
		// preferTaproot would steer every open into a taproot v2
		// negotiation that fails closed at the commitment stage. Masking
		// preserves what this configuration had before the lift: generic
		// opens ride the working v1 taproot path.
		const node = new LightningNode({
			...makeNodeConfig(21, { storage, recovery: quorumRecovery() }),
			preferTaproot: true
		});
		node.on('node:error', () => {});
		expect(
			localFeaturesOf(node).hasFeature(Feature.DUAL_FUND),
			'the bit stays masked for quorum + preferTaproot'
		).to.equal(false);
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
			channelId: deriveV2TemporaryChannelId(
				peerSide.basepoints.revocationBasepoint
			),
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
			channelFlags: 1,
			// BOLT 2 makes channel_type REQUIRED on open_channel2.
			channelType: Buffer.from('1000', 'hex')
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

	it('still refuses to come up over a legacy RECORD-LESS v2 open', function () {
		const storage = openStorage();
		// A row WITHOUT the durable v2InFlight record cannot actually
		// resume: it restores without a session, rejects a retransmitted
		// tx_signatures, and ignores funding confirmation, and it may
		// already have crossed commitment_signed. Quorum must not carry it
		// (a snapshot would claim an exactness the row cannot deliver);
		// the RECORDED row two tests down is the one that comes up.
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
		).to.throw(/no durable in-flight record is in progress/);

		// And the same database comes up fine in async-remote, which is
		// where the operator finishes or abandons it.
		const asyncNode = new LightningNode(
			makeNodeConfig(17, { storage, recovery: { enabled: true } })
		);
		asyncNode.on('node:error', () => {});
		expect(asyncNode.getChannelManager().listChannels()).to.have.length(1);
		asyncNode.destroy();
		storage.close();
	});

	it('refuses a record-less DUAL_FUNDING_V2 row BEFORE restore deletes it', function () {
		const storage = openStorage();
		// Restoration removes record-less DUAL_FUNDING_V2 rows durably (RBF
		// residue) and can journal frames while doing it. The preflight has
		// to run first: it throws with the DATABASE UNTOUCHED, so the
		// operator's async-remote retry still finds the row and takes the
		// ordinary residue path.
		const inFlight = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(23).basepoints,
			localPerCommitmentSeed: makeSeed(23)
		});
		inFlight.channelId = crypto.randomBytes(32);
		inFlight.state = ChannelState.DUAL_FUNDING_V2;
		const idHex = inFlight.channelId.toString('hex');
		storage.saveChannel(idHex, inFlight, '02'.repeat(33));

		expect(
			() =>
				new LightningNode(
					makeNodeConfig(23, {
						storage,
						recovery: quorumRecovery()
					})
				)
		).to.throw(/no durable in-flight record is in progress/);
		// The refusal fired BEFORE restoration: the row is still there.
		expect(
			storage.loadAllChannels().map((row) => row.channelId),
			'the preflight left the database untouched'
		).to.deep.equal([idHex]);

		// Async-remote takes the ordinary residue path: the row is removed
		// durably at restore, nothing is tracked.
		const asyncNode = new LightningNode(
			makeNodeConfig(23, { storage, recovery: { enabled: true } })
		);
		asyncNode.on('node:error', () => {});
		expect(asyncNode.getChannelManager().listChannels()).to.have.length(0);
		expect(storage.loadAllChannels()).to.have.length(0);
		asyncNode.destroy();
	});

	it('refuses a record-less v2 row even past tx_signatures states', function () {
		// AWAITING_FUNDING_CONFIRMED and AWAITING_CHANNEL_READY with
		// fundingVersion 2 and no record: a healthy post-record open
		// carries v2InFlight until NORMAL, so these shapes are legacy rows,
		// and they cannot answer a peer's next_funding (the splice handler
		// replies tx_abort). Quorum refuses both.
		for (const laterState of [
			ChannelState.AWAITING_FUNDING_CONFIRMED,
			ChannelState.AWAITING_CHANNEL_READY
		]) {
			const storage = openStorage();
			const inFlight = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 150_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(24).basepoints,
				localPerCommitmentSeed: makeSeed(24)
			});
			inFlight.channelId = crypto.randomBytes(32);
			inFlight.state = laterState;
			inFlight.fundingVersion = 2;
			storage.saveChannel(
				inFlight.channelId.toString('hex'),
				inFlight,
				'02'.repeat(33)
			);

			expect(
				() =>
					new LightningNode(
						makeNodeConfig(24, {
							storage,
							recovery: quorumRecovery()
						})
					),
				`refuses ${laterState}`
			).to.throw(/no durable in-flight record is in progress/);

			// Async-remote comes up over it for the operator to finish.
			const asyncNode = new LightningNode(
				makeNodeConfig(24, { storage, recovery: { enabled: true } })
			);
			asyncNode.on('node:error', () => {});
			expect(asyncNode.getChannelManager().listChannels()).to.have.length(1);
			asyncNode.destroy();
		}
	});

	it('unwraps a row stored mid-reestablish to the state it returns to', function () {
		const storage = openStorage();
		// A crash while AWAITING_REESTABLISH persists that state with the
		// original underneath; the preflight must judge the underlying one.
		const inFlight = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(33).basepoints,
			localPerCommitmentSeed: makeSeed(33)
		});
		inFlight.channelId = crypto.randomBytes(32);
		inFlight.state = ChannelState.AWAITING_REESTABLISH;
		inFlight.preReestablishState = ChannelState.AWAITING_TX_SIGNATURES;
		storage.saveChannel(
			inFlight.channelId.toString('hex'),
			inFlight,
			'02'.repeat(33)
		);

		expect(
			() =>
				new LightningNode(
					makeNodeConfig(33, {
						storage,
						recovery: quorumRecovery()
					})
				)
		).to.throw(/no durable in-flight record is in progress/);
		storage.close();
	});

	it('a database already sticky in quorum still boots over a legacy record-less v2 row', function () {
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-sticky-')),
			'node.db'
		);
		// Life 1: an ordinary quorum run writes a REAL quorum frame, which
		// is what makes the chain sticky.
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(28, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(60).toString('hex'),
					preimage: makeSeed(61)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed, 'a real quorum frame landed').to.equal(true);
		node1.destroy();

		// The upgrade shape: a pre-record v2 row sits in a database whose
		// chain already promised quorum (it passed the pre-preflight guard
		// of an earlier release and frames were written since).
		const s2 = new SqliteStorage(dbPath);
		s2.open();
		const legacy = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(29).basepoints,
			localPerCommitmentSeed: makeSeed(29)
		});
		legacy.channelId = crypto.randomBytes(32);
		legacy.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		legacy.fundingVersion = 2;
		s2.saveChannel(legacy.channelId.toString('hex'), legacy, '02'.repeat(33));
		s2.close();

		// Async-remote is NOT an exit here: the sticky rule refuses to run
		// this chain unbarriered. This is exactly why the preflight must
		// not refuse quorum startup for this database.
		const s3 = new SqliteStorage(dbPath);
		s3.open();
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(28, { storage: s3, recovery: { enabled: true } })
				)
		).to.throw(/quorum mode but no enforcing/);
		s3.close();

		// Quorum still boots: the preflight carries the row loudly instead
		// of leaving the database with no startup path, and the row takes
		// its ordinary disposition.
		const s4 = new SqliteStorage(dbPath);
		s4.open();
		const node2 = new LightningNode(
			makeNodeConfig(28, { storage: s4, recovery: quorumRecovery() })
		);
		node2.on('node:error', () => {});
		expect(node2.getChannelManager().listChannels()).to.have.length(1);

		// And the carried row is QUORUM-DURABLE, not merely restored: the
		// peer may hold a fully signed funding tx for it, so a guardian
		// reconstruction that omitted the channel would forget state the
		// peer can put on chain. The startup carriage appends it to the
		// journal, so frames alone rebuild it.
		const journal = (
			node2 as unknown as {
				recovery: {
					options: { journal?: { loadVerifiedFrames: () => unknown } };
				};
			}
		).recovery.options.journal;
		expect(journal, 'the node journals recovery frames').to.not.equal(
			undefined
		);
		const rebuilt = new SqliteStorage(':memory:');
		rebuilt.open();
		reconstructFromFrames(
			rebuilt,
			journal!.loadVerifiedFrames() as Parameters<
				typeof reconstructFromFrames
			>[1]
		);
		expect(
			rebuilt.loadAllChannels().map((row) => row.channelId),
			'guardian reconstruction includes the carried channel'
		).to.include(legacy.channelId.toString('hex'));
		rebuilt.close();
		node2.destroy();
	});

	it('a wrapped record-less DUAL row takes the residue deletion, not a phantom restore', function () {
		// Stored mid-reestablish, the row names DUAL_FUNDING_V2 underneath;
		// restoration must judge THAT state and remove the residue, in
		// async-remote and in a sticky-quorum carry alike.
		const buildRow = (seedId: number): ReturnType<typeof createOpenerState> => {
			const row = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 150_000n,
				pushMsat: 0n,
				localConfig: { ...DEFAULT_CHANNEL_CONFIG },
				localBasepoints: makeBasepoints(seedId).basepoints,
				localPerCommitmentSeed: makeSeed(seedId)
			});
			row.channelId = crypto.randomBytes(32);
			row.state = ChannelState.AWAITING_REESTABLISH;
			row.preReestablishState = ChannelState.DUAL_FUNDING_V2;
			return row;
		};

		// Async-remote: deleted at restore, never tracked, never stored.
		const asyncStorage = openStorage();
		const asyncRow = buildRow(34);
		asyncStorage.saveChannel(
			asyncRow.channelId!.toString('hex'),
			asyncRow,
			'02'.repeat(33)
		);
		const asyncNode = new LightningNode(
			makeNodeConfig(34, { storage: asyncStorage, recovery: { enabled: true } })
		);
		asyncNode.on('node:error', () => {});
		expect(asyncNode.getChannelManager().listChannels()).to.have.length(0);
		expect(asyncStorage.loadAllChannels()).to.have.length(0);
		asyncNode.destroy();

		// Sticky quorum: the preflight carries it (unwrapping to judge it),
		// and restoration still deletes the residue instead of restoring a
		// phantom that answers nothing.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-wrapdual-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(35, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(62).toString('hex'),
					preimage: makeSeed(63)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		node1.destroy();

		const s2 = new SqliteStorage(dbPath);
		s2.open();
		const stickyRow = buildRow(36);
		s2.saveChannel(
			stickyRow.channelId!.toString('hex'),
			stickyRow,
			'02'.repeat(33)
		);
		s2.close();

		const s3 = new SqliteStorage(dbPath);
		s3.open();
		const node2 = new LightningNode(
			makeNodeConfig(35, { storage: s3, recovery: quorumRecovery() })
		);
		node2.on('node:error', () => {});
		expect(
			node2.getChannelManager().listChannels(),
			'no phantom channel is tracked'
		).to.have.length(0);
		expect(
			s3.loadAllChannels(),
			'the residue row was removed durably'
		).to.have.length(0);
		// A DELETION-ONLY carry still gates: the deletion frame and the
		// snapshot that carries the burned index are unreceipted, so the
		// node must quarantine on the journal tip even though no repair
		// mutations were committed.
		expect(
			(node2 as unknown as { startupRepairPending: boolean })
				.startupRepairPending,
			'deletion-only dispositions still await their receipt'
		).to.equal(true);
		node2.destroy();

		// THE RECEIPT NEVER LANDED (the stub replicator never confirms).
		// The next boot finds no carried rows and a consumed schema marker,
		// so only the PERSISTED repair tail can remember that the guardians
		// still owe a receipt; without it this reboot would open clean.
		const s4 = new SqliteStorage(dbPath);
		s4.open();
		const node3 = new LightningNode(
			makeNodeConfig(35, { storage: s4, recovery: quorumRecovery() })
		);
		node3.on('node:error', () => {});
		expect(
			(node3 as unknown as { startupRepairPending: boolean })
				.startupRepairPending,
			'the persisted tail survives the restart and re-quarantines'
		).to.equal(true);
		node3.destroy();
	});

	it('an unverifiable journal tip refuses startup while a repair is owed', function () {
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-badtip-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(45, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(72).toString('hex'),
					preimage: makeSeed(73)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		node1.destroy();

		// A repair is owed (persisted tail) but the tip no longer verifies
		// (its recorded hash does not match the stored frame): there is
		// nothing sound to wait on, so startup must refuse, not proceed.
		const s2 = new SqliteStorage(dbPath);
		s2.open();
		s2.setRecoveryMeta!('startup_repair_tail', '1');
		s2.setRecoveryMeta!('journal_tip_hash', 'ff'.repeat(32));
		s2.close();

		const s3 = new SqliteStorage(dbPath);
		s3.open();
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(45, { storage: s3, recovery: quorumRecovery() })
				)
		).to.throw(/journal tip cannot be verified/);
		s3.close();
	});

	it('persists repair intent BEFORE consuming triggers, so a crash still re-quarantines', function () {
		// The schema migration consumes its marker and restore consumes the
		// carried rows; if the concrete tail write is lost after that, the
		// intent marker written FIRST must still make the next boot gate.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-intent-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(47, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(76).toString('hex'),
					preimage: makeSeed(77)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		node1.destroy();

		// An old-schema journal (owes the schema repair) and no carried row.
		const s2 = new SqliteStorage(dbPath);
		s2.open();
		s2.setRecoveryMeta!('journal_snapshot_schema', '1');
		s2.close();

		// Fail the CONCRETE tail write (the numeric one), letting the
		// intent marker ('owed') and the migration land first.
		const s3 = new SqliteStorage(dbPath);
		s3.open();
		const realSet = s3.setRecoveryMeta!.bind(s3);
		s3.setRecoveryMeta = (key: string, value: string): void => {
			if (key === 'startup_repair_tail' && /^[0-9]+$/.test(value)) {
				throw new Error('disk says no');
			}
			realSet(key, value);
		};
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(47, { storage: s3, recovery: quorumRecovery() })
				)
		).to.throw();
		s3.close();

		// The intent marker survived: the next (healthy) boot still gates
		// even though the schema marker is now consumed and no row carried.
		const s4 = new SqliteStorage(dbPath);
		s4.open();
		expect(
			s4.getRecoveryMeta!('startup_repair_tail'),
			'the owed intent marker persisted'
		).to.equal('owed');
		const node2 = new LightningNode(
			makeNodeConfig(47, { storage: s4, recovery: quorumRecovery() })
		);
		node2.on('node:error', () => {});
		expect(
			(node2 as unknown as { startupRepairPending: boolean })
				.startupRepairPending,
			'the persisted intent re-quarantines the reboot'
		).to.equal(true);
		node2.destroy();
	});

	it('a failed schema migration rolls back atomically and retries', function () {
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-atomic-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(46, { storage: s1, recovery: { enabled: true } })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(74).toString('hex'),
					preimage: makeSeed(75)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		node1.destroy();

		const s2 = new SqliteStorage(dbPath);
		s2.open();
		s2.setRecoveryMeta!('journal_snapshot_schema', '1');
		const frameCountBefore = s2.loadRecoveryFrames!(0).length;
		s2.close();

		// The marker write explodes mid-migration: the WHOLE transaction
		// must roll back, leaving the journal exactly as it was.
		const s3 = new SqliteStorage(dbPath);
		s3.open();
		const realSetMeta = s3.setRecoveryMeta!.bind(s3);
		s3.setRecoveryMeta = (key: string, value: string): void => {
			if (key === 'journal_snapshot_schema' && value === '2') {
				throw new Error('disk says no');
			}
			realSetMeta(key, value);
		};
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(46, { storage: s3, recovery: { enabled: true } })
				)
		).to.throw(/disk says no/);
		s3.close();

		// Nothing partial: same frame count, old marker, tip verifiable.
		const s4 = new SqliteStorage(dbPath);
		s4.open();
		expect(s4.loadRecoveryFrames!(0).length, 'no stranded frame').to.equal(
			frameCountBefore
		);
		expect(s4.getRecoveryMeta!('journal_snapshot_schema')).to.equal('1');
		// And the unpatched retry completes the migration.
		const node2 = new LightningNode(
			makeNodeConfig(46, { storage: s4, recovery: { enabled: true } })
		);
		node2.on('node:error', () => {});
		expect(s4.getRecoveryMeta!('journal_snapshot_schema')).to.equal('2');
		// The repair snapshot compacts the deltas below it, so the count
		// SHRINKS; what matters is that the journal stayed verifiable and
		// the newest retained frame is the fresh snapshot.
		expect(
			s4.loadRecoveryFrames!(0).length,
			'the repaired journal retains a verifiable chain'
		).to.be.at.least(1);
		node2.destroy();
	});

	it('a carried row whose deletion disposition fails refuses startup', function () {
		// Sticky quorum + a wrapped-DUAL residue whose durable deletion
		// cannot land: the disposition is not durable, so the node must not
		// come up over it.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-delfail-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(37, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(68).toString('hex'),
					preimage: makeSeed(69)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		node1.destroy();

		const s2 = new SqliteStorage(dbPath);
		s2.open();
		const residue = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(38).basepoints,
			localPerCommitmentSeed: makeSeed(38)
		});
		residue.channelId = crypto.randomBytes(32);
		residue.state = ChannelState.AWAITING_REESTABLISH;
		residue.preReestablishState = ChannelState.DUAL_FUNDING_V2;
		const residueId = residue.channelId.toString('hex');
		s2.saveChannel(residueId, residue, '02'.repeat(33));
		s2.close();

		const s3 = new SqliteStorage(dbPath);
		s3.open();
		const realDelete = s3.deleteChannel.bind(s3);
		s3.deleteChannel = (id: string): void => {
			if (id === residueId) throw new Error('disk says no');
			realDelete(id);
		};
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(37, { storage: s3, recovery: quorumRecovery() })
				)
		).to.throw(/could not be dispositioned durably/);
		s3.close();
	});

	it('refuses to downgrade a FUTURE recovery schema version', function () {
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-future-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(48, { storage: s1, recovery: { enabled: true } })
		);
		node1.on('node:error', () => {});
		recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(78).toString('hex'),
					preimage: makeSeed(79)
				}
			],
			outboundMessages: []
		});
		node1.destroy();

		// A newer release wrote schema '3'; this build must NOT compact with
		// its version-2 shape and rewrite the marker down to 2. Seed a
		// record-less DUAL_FUNDING_V2 row too: restoration deletes those
		// durably and can journal (and even snapshot) while doing it, so the
		// refusal must land BEFORE restore runs, or the restore-triggered
		// snapshot stamps the current schema over the marker this build
		// never validated and the startup sails through.
		const s2 = new SqliteStorage(dbPath);
		s2.open();
		const residue = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(48).basepoints,
			localPerCommitmentSeed: makeSeed(48)
		});
		residue.channelId = crypto.randomBytes(32);
		residue.state = ChannelState.DUAL_FUNDING_V2;
		const residueIdHex = residue.channelId.toString('hex');
		s2.saveChannel(residueIdHex, residue, '02'.repeat(33));
		s2.setRecoveryMeta!('journal_snapshot_schema', '3');
		const framesBefore = s2.loadRecoveryFrames!(0).length;
		s2.close();

		const s3 = new SqliteStorage(dbPath);
		s3.open();
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(48, { storage: s3, recovery: { enabled: true } })
				)
		).to.throw(/not one this release can migrate/);
		// Untouched: same marker, same frame count, the residue row intact.
		expect(s3.getRecoveryMeta!('journal_snapshot_schema')).to.equal('3');
		expect(s3.loadRecoveryFrames!(0).length).to.equal(framesBefore);
		expect(
			s3.loadAllChannels().map((row) => row.channelId),
			'the refusal fired before restore touched the database'
		).to.deep.equal([residueIdHex]);
		s3.close();
	});

	it('refuses malformed schema markers instead of coercing them', function () {
		// Number-coercion would accept '-1', '1e0', '0x1' or '01' and then
		// destructively migrate a journal whose real version is unknowable.
		// Only the exact known representations may proceed.
		for (const bad of ['-1', '1e0', '0x1', '01', 'garbage']) {
			const dbPath = path.join(
				fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-malformed-')),
				'node.db'
			);
			const s1 = new SqliteStorage(dbPath);
			s1.open();
			const node1 = new LightningNode(
				makeNodeConfig(48, { storage: s1, recovery: { enabled: true } })
			);
			node1.on('node:error', () => {});
			recoveryOf(node1).commit({
				criticality: RecoveryCriticality.Important,
				mutations: [
					{
						type: 'payment_preimage',
						paymentHash: makeSeed(80).toString('hex'),
						preimage: makeSeed(81)
					}
				],
				outboundMessages: []
			});
			node1.destroy();

			const s2 = new SqliteStorage(dbPath);
			s2.open();
			s2.setRecoveryMeta!('journal_snapshot_schema', bad);
			const framesBefore = s2.loadRecoveryFrames!(0).length;
			s2.close();

			const s3 = new SqliteStorage(dbPath);
			s3.open();
			expect(
				() =>
					new LightningNode(
						makeNodeConfig(48, { storage: s3, recovery: { enabled: true } })
					),
				`marker '${bad}' must refuse`
			).to.throw(/not one this release can migrate/);
			expect(
				s3.getRecoveryMeta!('journal_snapshot_schema'),
				`marker '${bad}' left untouched`
			).to.equal(bad);
			expect(s3.loadRecoveryFrames!(0).length).to.equal(framesBefore);
			s3.close();
		}
	});

	it('refuses an unrecognized startup repair marker instead of guessing', function () {
		// The stored tail is either the bare 'owed' sentinel or a decimal
		// frame sequence. Treating arbitrary corruption as the sentinel
		// would invent a guardian obligation out of garbage; fail closed.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-badtail-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		s1.setRecoveryMeta!('startup_repair_tail', 'garbage');
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(49, { storage: s1, recovery: quorumRecovery() })
				)
		).to.throw(/startup repair marker/);
		expect(
			s1.getRecoveryMeta!('startup_repair_tail'),
			'the marker is preserved for inspection'
		).to.equal('garbage');
		s1.close();
	});

	it('consumes no trigger before the intent marker is durable', function () {
		// The bare sentinel write precedes BOTH trigger consumptions (the
		// schema migration and restore). A boot that cannot persist the
		// sentinel must refuse before consuming anything, or a crash there
		// leaves the guardians owed a receipt with no trigger left to
		// re-arm it.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-intentorder-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(54, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(90).toString('hex'),
					preimage: makeSeed(91)
				}
			],
			outboundMessages: []
		});
		node1.destroy();

		const s2 = new SqliteStorage(dbPath);
		s2.open();
		s2.setRecoveryMeta!('journal_snapshot_schema', '1');
		const realSet = s2.setRecoveryMeta!.bind(s2);
		s2.setRecoveryMeta = (key: string, value: string): void => {
			if (key === 'startup_repair_tail' && value === 'owed') {
				throw new Error('disk says no');
			}
			realSet(key, value);
		};
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(54, { storage: s2, recovery: quorumRecovery() })
				)
		).to.throw(/disk says no/);
		// Neither trigger was consumed: the old-schema marker is intact, so
		// a later boot still sees the whole repair owed.
		expect(
			s2.getRecoveryMeta!('journal_snapshot_schema'),
			'the schema trigger was not consumed before the intent write'
		).to.equal('1');
		s2.close();
	});

	it('never downgrades a stored numeric repair target to the bare sentinel', function () {
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-numtail-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(53, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(92).toString('hex'),
					preimage: makeSeed(93)
				}
			],
			outboundMessages: []
		});
		node1.destroy();

		// The stored target sits ABOVE the local tip (a prior boot computed
		// it from a higher intent). Crash the boot before the concrete tail
		// write lands: whatever happens, the stored target must never have
		// shrunk in the meantime, or a restart in that window would gate on
		// the lower tip and lift quarantine before the real target was
		// receipted.
		const s2 = new SqliteStorage(dbPath);
		s2.open();
		s2.setRecoveryMeta!('startup_repair_tail', '999999');
		const realSet = s2.setRecoveryMeta!.bind(s2);
		s2.setRecoveryMeta = (key: string, value: string): void => {
			if (key === 'startup_repair_tail' && /^[0-9]+$/.test(value)) {
				throw new Error('disk says no');
			}
			realSet(key, value);
		};
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(53, { storage: s2, recovery: quorumRecovery() })
				)
		).to.throw();
		expect(
			s2.getRecoveryMeta!('startup_repair_tail'),
			'the numeric target survived the crashed boot un-shrunk'
		).to.equal('999999');
		s2.close();

		// A healthy boot gates on the HIGHER of tip and stored target, and
		// keeps the concrete number durable.
		const s3 = new SqliteStorage(dbPath);
		s3.open();
		const node2 = new LightningNode(
			makeNodeConfig(53, { storage: s3, recovery: quorumRecovery() })
		);
		node2.on('node:error', () => {});
		expect(
			(node2 as unknown as { startupRepairPending: boolean })
				.startupRepairPending,
			'quarantined behind the stored target'
		).to.equal(true);
		expect(s3.getRecoveryMeta!('startup_repair_tail')).to.equal('999999');
		node2.destroy();
		s3.close();
	});

	it('restoration carries the snapshot schema and refuses an unknown one', function () {
		// The local marker is metadata and dies with the device; what
		// survives is the schema declaration INSIDE the authenticated
		// snapshot frame.
		const s1 = openStorage();
		const node1 = new LightningNode(
			makeNodeConfig(52, { storage: s1, recovery: { enabled: true } })
		);
		node1.on('node:error', () => {});
		recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(94).toString('hex'),
					preimage: makeSeed(95)
				}
			],
			outboundMessages: []
		});
		const journal = (
			node1 as unknown as {
				recovery: {
					options: { journal?: { loadVerifiedFrames: () => unknown } };
				};
			}
		).recovery.options.journal;
		const frames = journal!.loadVerifiedFrames() as Parameters<
			typeof reconstructFromFrames
		>[1];
		node1.destroy();

		// A device rebuilt from frames alone knows its schema again: the
		// restored journal is NOT mistaken for pre-versioning legacy.
		const rebuilt = new SqliteStorage(':memory:');
		rebuilt.open();
		reconstructFromFrames(rebuilt, frames);
		expect(
			rebuilt.getRecoveryMeta!('journal_snapshot_schema'),
			'the authenticated snapshot reinstalled the marker'
		).to.equal('2');
		rebuilt.close();

		// A FUTURE release's snapshot refuses reconstruction outright:
		// replaying it with this build's shape would silently drop whatever
		// that shape added.
		const tampered = (
			frames as Array<{ snapshot?: { schemaVersion?: string } }>
		).map((f) =>
			f.snapshot ? { ...f, snapshot: { ...f.snapshot, schemaVersion: '3' } } : f
		);
		const rebuilt2 = new SqliteStorage(':memory:');
		rebuilt2.open();
		expect(() =>
			reconstructFromFrames(
				rebuilt2,
				tampered as Parameters<typeof reconstructFromFrames>[1]
			)
		).to.throw(/cannot restore/);
		expect(rebuilt2.loadAllChannels()).to.have.length(0);
		rebuilt2.close();

		// And a LEGACY snapshot (no declaration) refuses too: snapshots
		// from that era omitted deleted channels' burned key indices, so
		// rebuilding from one and then stamping it current would launder
		// the gap into a schema-2 journal and permit key-index reuse.
		// Local journals of the same vintage stay migratable because their
		// TABLE still holds the rows; a remote snapshot has already lost
		// them, so there is nothing to migrate from.
		const legacy = (
			frames as Array<{ snapshot?: { schemaVersion?: string } }>
		).map((f) => {
			if (!f.snapshot) return f;
			const { schemaVersion: _dropped, ...rest } = f.snapshot;
			return { ...f, snapshot: rest };
		});
		const rebuilt3 = new SqliteStorage(':memory:');
		rebuilt3.open();
		expect(() =>
			reconstructFromFrames(
				rebuilt3,
				legacy as Parameters<typeof reconstructFromFrames>[1]
			)
		).to.throw(/burned key indices/);
		expect(rebuilt3.loadAllChannels()).to.have.length(0);
		rebuilt3.close();
		s1.close();
	});

	it('a direct journal write refuses an unmigratable schema marker', function () {
		// The node's startup probe is optional API; a direct
		// RecoveryManager over the same storage must hit the same wall at
		// the journal's own write boundary.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-directwrite-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(51, { storage: s1, recovery: { enabled: true } })
		);
		node1.on('node:error', () => {});
		recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(96).toString('hex'),
					preimage: makeSeed(97)
				}
			],
			outboundMessages: []
		});
		node1.destroy();

		const s2 = new SqliteStorage(dbPath);
		s2.open();
		s2.setRecoveryMeta!('journal_snapshot_schema', '3');
		const framesBefore = s2.loadRecoveryFrames!(0).length;
		const journal = new RecoveryJournal(
			s2,
			makeSeed(98),
			getPublicKey(makeSeed(99)),
			makeSeed(100)
		);
		const manager = new RecoveryManager(s2, { journal });
		const result = manager.commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(101).toString('hex'),
					preimage: makeSeed(102)
				}
			],
			outboundMessages: []
		});
		expect(result.committed, 'the direct commit is refused').to.equal(false);
		expect(String(result.error?.message)).to.match(
			/not one this release can migrate/
		);
		// Untouched: same marker, same frame count.
		expect(s2.getRecoveryMeta!('journal_snapshot_schema')).to.equal('3');
		expect(s2.loadRecoveryFrames!(0).length).to.equal(framesBefore);
		s2.close();
	});

	it('waitForReady fast paths never outrun the startup repair quarantine', async function () {
		// Boot a REAL quarantined node (owed marker, unreleasable stub
		// barrier) with zero channels: exactly the shape the no-channel
		// fast path would wave through without the guard.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-ready-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(50, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(82).toString('hex'),
					preimage: makeSeed(83)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		node1.destroy();

		const s2 = new SqliteStorage(dbPath);
		s2.open();
		s2.setRecoveryMeta!('startup_repair_tail', 'owed');
		const node2 = new LightningNode(
			makeNodeConfig(50, { storage: s2, recovery: quorumRecovery() })
		);
		node2.on('node:error', () => {});
		try {
			const pending = (node2 as unknown as { startupRepairPending: boolean })
				.startupRepairPending;
			expect(pending, 'the node came up quarantined').to.equal(true);
			let readyFired = false;
			node2.on('node:ready', () => {
				readyFired = true;
			});

			// No channels at all, and still NOT ready.
			expect(node2.getChannelManager().listChannels()).to.have.length(0);
			let timedOut = false;
			await node2.waitForReady(150).catch(() => {
				timedOut = true;
			});
			expect(timedOut, 'no-channel fast path refused').to.equal(true);
			expect(readyFired).to.equal(false);

			// A NORMAL channel, and still NOT ready either.
			(
				node2.getChannelManager() as unknown as {
					listChannels(): unknown[];
				}
			).listChannels = () => [
				{ getState: (): ChannelState => ChannelState.NORMAL }
			];
			timedOut = false;
			await node2.waitForReady(150).catch(() => {
				timedOut = true;
			});
			expect(timedOut, 'NORMAL-channel fast path refused').to.equal(true);
			expect(readyFired).to.equal(false);

			// Quarantine lifted (the receipt path does this): the very same
			// fast path is ready immediately and the event fires.
			(
				node2 as unknown as { startupRepairPending: boolean }
			).startupRepairPending = false;
			await node2.waitForReady(2000);
			await new Promise((resolve) => setTimeout(resolve, 20));
			expect(readyFired, 'ready fires once the quarantine lifts').to.equal(
				true
			);
		} finally {
			node2.destroy();
			s2.close();
		}
	});

	it('an upgraded journal writes the schema-repair snapshot and reconstruction keeps burned indices', function () {
		// A head compacted by an older release omitted deleted channels'
		// key-index rows. On the first boot of a release that knows better,
		// the journal must append a fresh full snapshot even if the node is
		// otherwise quiet, and reconstruction must then preserve the burned
		// high-water mark.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-schema-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(39, { storage: s1, recovery: { enabled: true } })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(70).toString('hex'),
					preimage: makeSeed(71)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		node1.destroy();

		// The upgrade shape: a burned index whose channel is long gone, and
		// a journal whose snapshot-schema marker predates the fix.
		const s2 = new SqliteStorage(dbPath);
		s2.open();
		s2.saveChannelKeyIndex('feed'.repeat(16), 7);
		s2.setRecoveryMeta!('journal_snapshot_schema', '1');
		s2.close();

		const s3 = new SqliteStorage(dbPath);
		s3.open();
		const node2 = new LightningNode(
			makeNodeConfig(39, { storage: s3, recovery: { enabled: true } })
		);
		node2.on('node:error', () => {});
		const journal = (
			node2 as unknown as {
				recovery: {
					options: { journal?: { loadVerifiedFrames: () => unknown } };
				};
			}
		).recovery.options.journal;
		const rebuilt = new SqliteStorage(':memory:');
		rebuilt.open();
		reconstructFromFrames(
			rebuilt,
			journal!.loadVerifiedFrames() as Parameters<
				typeof reconstructFromFrames
			>[1]
		);
		expect(
			rebuilt.loadNextChannelIndex(),
			'the burned index survives reconstruction of the repaired head'
		).to.be.at.least(8);
		rebuilt.close();
		node2.destroy();
	});

	it('the carried row is guardian-durable BEFORE the node talks to anyone, and burned key indices survive', async function () {
		this.timeout(30_000);
		// The full upgrade arc against REAL guardians: a sticky-quorum
		// database gains (a) a record-less AFC row the peer may be able to
		// fund and (b) a wrapped-DUAL residue row whose key index 7 is
		// burned. The boot must journal the carried row, stay quarantined
		// until the repair frame is quorum-RECEIPTED, and a guardian-only
		// RestoreDriver must then rebuild BOTH the carried channel and the
		// key-index high-water mark.
		const secrets = [1, 2, 3].map((i) =>
			crypto.createHash('sha256').update(`p6v2-guardian-${i}`).digest()
		);
		const ids = secrets.map((secret) => xOnlyFromSecret(secret));
		const setId = computeGuardianSetId({
			...CRASH_V1_PROFILE,
			guardianIds: ids
		});
		const context = { guardianSetId: setId, members: ids };
		let now = 2_600_000_000_000n;
		const clock = (): bigint => ++now;
		const served = await Promise.all(
			secrets.map(async (secret, index) => {
				const guardian = new ReferenceGuardian({
					path: ':memory:',
					guardianSecret: secret,
					members: ids,
					clock
				});
				const server = new GuardianHttpServer({ guardian });
				const port = await server.listen(0);
				return {
					guardian,
					server,
					bound: {
						client: new GuardianClient({
							url: `http://127.0.0.1:${port}`,
							guardianSetId: setId
						}),
						expectedGuardianId: ids[index]
					} as IBoundGuardianClient
				};
			})
		);
		const bound = served.map((entry) => entry.bound);
		const nodeSeed = 40;
		const nodePriv = crypto
			.createHash('sha256')
			.update(makeSeed(nodeSeed))
			.update(Buffer.from('node-identity'))
			.digest();
		const recoveryRoot = deriveRecoveryRoot(nodePriv);

		const realQuorum = (
			storage: SqliteStorage,
			lease: { value: IWriterLeaseKeys | null }
		): {
			recovery: INodeConfig['recovery'];
			replicator: GuardianReplicator;
		} => {
			const replicator = new GuardianReplicator({
				storage,
				guardians: bound,
				context,
				required: CRASH_V1_PROFILE.required,
				recoveryRoot,
				clock
			});
			const barrier = new DurabilityBarrier({
				durability: 'quorum',
				replicator,
				lease: () => lease.value,
				timeoutMs: 10_000,
				retryDelayMs: 50
			});
			return {
				recovery: {
					enabled: true,
					durability: 'quorum',
					barrier,
					snapshotIntervalFrames: 1
				},
				replicator
			};
		};

		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-guardians-')),
			'node.db'
		);
		// The writer lease refuses unencrypted storage.
		const dbKey = crypto
			.createHash('sha256')
			.update('p6v2-guardian-db-key')
			.digest();
		const openDb = (): SqliteStorage => {
			const db = new SqliteStorage(dbPath, undefined, {
				encryptionKey: dbKey
			});
			db.open();
			return db;
		};
		// Life 1: quorum runs for real; the namespace registers, a frame
		// lands, replication catches up.
		const s1 = openDb();
		const lease1: { value: IWriterLeaseKeys | null } = { value: null };
		const q1 = realQuorum(s1, lease1);
		const decision = await q1.replicator.ensureNamespace();
		expect(decision.outcome, 'namespace registered').to.equal('registered');
		lease1.value = (decision as { lease: IWriterLeaseKeys }).lease;
		const node1 = new LightningNode(
			makeNodeConfig(nodeSeed, { storage: s1, recovery: q1.recovery })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(64).toString('hex'),
					preimage: makeSeed(65)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		await q1.replicator.replicatePending(lease1.value!);
		node1.destroy();

		// The upgrade shape: a carried AFC row plus a wrapped-DUAL residue
		// row with key index 7 burned, both written OUTSIDE the journal.
		const s2 = openDb();
		const carried = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(41).basepoints,
			localPerCommitmentSeed: makeSeed(41)
		});
		carried.channelId = crypto.randomBytes(32);
		carried.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		carried.fundingVersion = 2;
		s2.saveChannel(carried.channelId.toString('hex'), carried, '02'.repeat(33));
		const residue = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(42).basepoints,
			localPerCommitmentSeed: makeSeed(42)
		});
		residue.channelId = crypto.randomBytes(32);
		residue.state = ChannelState.AWAITING_REESTABLISH;
		residue.preReestablishState = ChannelState.DUAL_FUNDING_V2;
		const residueId = residue.channelId.toString('hex');
		s2.saveChannel(residueId, residue, '02'.repeat(33));
		s2.saveChannelKeyIndex(residueId, 7);
		s2.close();

		// Life 2: the boot journals the carried row and stays quarantined
		// until the repair frame is receipted by the quorum.
		const s3 = openDb();
		const lease2: { value: IWriterLeaseKeys | null } = { value: null };
		const loaded = loadWriterLease(s3);
		expect(loaded.state, 'the lease survived').to.equal('present');
		lease2.value = (loaded as { lease: IWriterLeaseKeys }).lease;
		const q2 = realQuorum(s3, lease2);
		const node2 = new LightningNode(
			makeNodeConfig(nodeSeed, { storage: s3, recovery: q2.recovery })
		);
		node2.on('node:error', () => {});
		// The deferred bring-up must end deterministically even when the
		// reconnect pass explodes: contained as a node error, ready still
		// reported, quarantine still lifted.
		const nodeErrors: Array<{ code?: string }> = [];
		node2.on('node:error', (e: { code?: string }) => nodeErrors.push(e));
		let readyFired = false;
		node2.on('node:ready', () => {
			readyFired = true;
		});
		(
			node2 as unknown as { autoReconnectPeers: () => void }
		).autoReconnectPeers = () => {
			throw new Error('reconnect exploded');
		};
		const pendingOf = (n: LightningNode): boolean =>
			(n as unknown as { startupRepairPending: boolean }).startupRepairPending;
		expect(
			pendingOf(node2),
			'the node quarantines itself behind the repair frame'
		).to.equal(true);
		// Readiness must not outrun the quarantine, even on the no-channel
		// and NORMAL-channel fast paths, and the status surface reports it.
		expect(
			node2.getRecoveryStatus().startupRepairPending,
			'getRecoveryStatus reports the quarantine'
		).to.equal(true);
		let readyWhileQuarantined = false;
		node2.on('node:ready', () => {
			if (pendingOf(node2)) readyWhileQuarantined = true;
		});
		void node2.waitForReady(200).catch(() => undefined);
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(
			readyWhileQuarantined,
			'ready never fired while quarantined'
		).to.equal(false);
		const deadline = Date.now() + 15_000;
		while (pendingOf(node2) && Date.now() < deadline) {
			await new Promise((resolve) => setTimeout(resolve, 50));
		}
		expect(
			pendingOf(node2),
			'the repair frame was receipted and the quarantine lifted'
		).to.equal(false);
		expect(
			node2.getChannelManager().getChannel(carried.channelId),
			'the carried channel is tracked'
		).to.not.equal(undefined);
		expect(
			node2.getChannelManager().getChannel(residue.channelId),
			'the residue was deleted, not restored'
		).to.equal(undefined);
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(
			nodeErrors.some((e) => e.code === 'STARTUP_RECONNECT_FAILED'),
			'the throwing reconnect surfaced as a node error'
		).to.equal(true);
		expect(readyFired, 'the node still reported ready').to.equal(true);
		expect(
			s3.getRecoveryMeta!('startup_repair_tail') || '',
			'the persisted repair tail was cleared by the receipt'
		).to.equal('');
		node2.destroy();

		// Guardian-only restore: the device burns; the trio must give back
		// the carried channel AND the key-index high-water mark.
		const target = new SqliteStorage(':memory:');
		target.open();
		await new RestoreDriver({
			target,
			guardians: bound,
			context,
			required: CRASH_V1_PROFILE.required,
			recoveryRoot,
			nodeSecret: nodePriv,
			nodeId: getPublicKey(nodePriv),
			clock
		}).restore();
		expect(
			target.loadAllChannels().map((row) => row.channelId),
			'guardian-held frames rebuild the carried channel'
		).to.include(carried.channelId.toString('hex'));
		expect(
			target.loadNextChannelIndex(),
			'the burned key index survives reconstruction'
		).to.be.at.least(8);
		target.close();
		s3.close();
		for (const entry of served) {
			await entry.server.close();
			entry.guardian.close();
		}
	});

	it('a failed repair append refuses startup outright', function () {
		// Fail-closed: if the carried row cannot be journaled, the node must
		// not come up and start talking as if the repair had happened.
		const dbPath = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), 'p6v2-failrepair-')),
			'node.db'
		);
		const s1 = new SqliteStorage(dbPath);
		s1.open();
		const node1 = new LightningNode(
			makeNodeConfig(43, { storage: s1, recovery: quorumRecovery() })
		);
		node1.on('node:error', () => {});
		const committed = recoveryOf(node1).commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: makeSeed(66).toString('hex'),
					preimage: makeSeed(67)
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		node1.destroy();

		const s2 = new SqliteStorage(dbPath);
		s2.open();
		const carried = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(44).basepoints,
			localPerCommitmentSeed: makeSeed(44)
		});
		carried.channelId = crypto.randomBytes(32);
		carried.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		carried.fundingVersion = 2;
		s2.saveChannel(carried.channelId.toString('hex'), carried, '02'.repeat(33));
		s2.close();

		const s3 = new SqliteStorage(dbPath);
		s3.open();
		// The journal append fails exactly when the repair frame would be
		// written: the carried row's channel_state save inside the commit.
		const realSave = s3.saveChannel.bind(s3);
		const carriedId = carried.channelId.toString('hex');
		s3.saveChannel = (id: string, state: unknown, peer: string): void => {
			if (id === carriedId) throw new Error('disk says no');
			realSave(id, state as never, peer);
		};
		expect(
			() =>
				new LightningNode(
					makeNodeConfig(43, { storage: s3, recovery: quorumRecovery() })
				)
		).to.throw(/could not journal the carried v2 open/);
		s3.close();
	});

	it('leaves a v1 AWAITING_FUNDING_CONFIRMED row alone', function () {
		const storage = openStorage();
		// The later-state clauses are scoped to fundingVersion 2: an
		// ordinary v1 open awaiting depth resumes fine and must not trip
		// the preflight.
		const v1 = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 150_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(25).basepoints,
			localPerCommitmentSeed: makeSeed(25)
		});
		v1.channelId = crypto.randomBytes(32);
		v1.state = ChannelState.AWAITING_FUNDING_CONFIRMED;
		storage.saveChannel(v1.channelId.toString('hex'), v1, '02'.repeat(33));

		const node = quorumNode(25, storage);
		expect(node.getChannelManager().listChannels()).to.have.length(1);
		node.destroy();
	});

	it('a masked node refuses an inbound open_channel2 before it allocates anything', async function () {
		const storage = openStorage();
		// quorum + preferTaproot masks option_dual_fund; features are
		// advisory on the wire, so the handler must hold the line itself:
		// no keys derived, no temp channel, no row, and a WIRE error so the
		// opener is not left parked in DUAL_FUNDING_V2.
		let derived = 0;
		const node = new LightningNode({
			...makeNodeConfig(26, {
				storage,
				recovery: quorumRecovery(),
				fundingProvider: fundingProviderWith(makeWalletInput(200_000))
			}),
			preferTaproot: true,
			channelKeyDeriver: (index: number) => {
				derived++;
				const bp = makeBasepoints(70 + index);
				return {
					basepoints: bp.basepoints,
					perCommitmentSeed: makeSeed(170 + index),
					fundingPrivkey: bp.fundingPrivkey,
					htlcBasepointSecret: bp.htlcSecret
				};
			}
		});
		node.on('node:error', () => {});
		node.on('error', () => {});
		const manager = managerOf(node);
		const errors: string[] = [];
		manager.on('error', (_id: Buffer | null, message: string) => {
			errors.push(message);
		});
		const sent: number[] = [];
		node.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});

		const peerSide = makeBasepoints(27);
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
		await settle(() => errors.length > 0, 1500);

		expect(errors.join(' ')).to.contain('does not advertise option_dual_fund');
		// The refusal is peer-visible, and nothing was allocated for it:
		// no accept, no key index burnt, no channel, no row.
		expect(sent, 'a wire error went out').to.include(MessageType.ERROR);
		expect(sent).to.not.include(MessageType.ACCEPT_CHANNEL2);
		expect(derived, 'no channel keys were derived').to.equal(0);
		expect(manager.listChannels()).to.have.length(0);
		expect(storage.loadAllChannels()).to.have.length(0);

		node.destroy();
	});

	it('refuses an inbound open_channel2 from a peer whose init lacked the bit', async function () {
		const storage = openStorage();
		// We advertise option_dual_fund, the PEER did not: v2 establishment
		// is conditioned on the NEGOTIATED feature, so the proposal is out
		// of contract however it arrived, and the refusal goes on the wire.
		const node = quorumNode(30, storage);
		const manager = managerOf(node);
		const errors: string[] = [];
		manager.on('error', (_id: Buffer | null, message: string) => {
			errors.push(message);
		});
		const sent: number[] = [];
		(manager as unknown as { peerManager: unknown }).peerManager = {
			getPeer: () => ({
				getRemoteInit: () => ({ features: FeatureFlags.empty() })
			}),
			sendToPeer: (_pk: string, type: number) => {
				sent.push(type);
			}
		};

		const peerSide = makeBasepoints(31);
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
		await settle(() => errors.length > 0, 1500);

		expect(errors.join(' ')).to.contain(
			'the peer did not advertise option_dual_fund'
		);
		expect(sent, 'a wire error went out').to.include(MessageType.ERROR);
		expect(sent).to.not.include(MessageType.ACCEPT_CHANNEL2);
		expect(manager.listChannels()).to.have.length(0);
		expect(storage.loadAllChannels()).to.have.length(0);

		node.destroy();
		storage.close();
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
