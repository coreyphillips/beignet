/**
 * Taproot SCB-recovery sweep tests (offline, deterministic).
 *
 * A channel restored from a static channel backup has NO remote basepoints and
 * never learns a per-commitment point; when the peer force-closes, the funding
 * spend is classified THEIR_FUTURE_COMMITMENT and only our to_remote may be
 * swept. For SIMPLE TAPROOT channels that to_remote is a NUMS-internal-key
 * P2TR whose single 1-CSV leaf pays our STATIC payment basepoint, so it is
 * locatable and spendable from the SCB entry alone (channelKeyIndex + seed).
 * These tests pin: output location, key derivation (node-level AND per-channel
 * deriver keys), sweep construction (1-CSV sequence, witness shape, valid
 * BIP340 signature, fee handling), and the CSV-held release through the
 * monitor - mirroring tests/lightning/scb-restore.test.ts for the taproot
 * channel type.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { IPerChannelKeys } from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import {
	classifyCommitmentTx,
	classifyOutputs,
	resolveTheirCurrentCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import { estimateSweepVbytes } from '../../src/lightning/chain/sweep';
import {
	CommitmentType,
	ChainActionType,
	OutputType,
	OutputStatus
} from '../../src/lightning/chain/types';
import {
	buildTaprootToRemoteOutput,
	buildTaprootToRemoteScript,
	toXOnly,
	TAPLEAF_VERSION
} from '../../src/lightning/script/commitment-taproot';
import {
	tapleafHash,
	verifyTaprootHtlcLeaf
} from '../../src/lightning/script/htlc-taproot';
import {
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IScbChannelEntry } from '../../src/lightning/backup/scb';

bitcoin.initEccLib(ecc);

// ─────────────── Harness (mirrors tests/lightning/scb-restore.test.ts) ───────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-scb-recovery-seed-${id}`))
		.digest();
}

function makePrivkeys(seed: Buffer): Buffer[] {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return keys;
}

function makeBasepoints(privkeys: Buffer[]): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(privkeys[0]),
		revocationBasepoint: getPublicKey(privkeys[1]),
		paymentBasepoint: getPublicKey(privkeys[2]),
		delayedPaymentBasepoint: getPublicKey(privkeys[3]),
		htlcBasepoint: getPublicKey(privkeys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const privkeys = makePrivkeys(seed);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(privkeys),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: privkeys[0],
		revocationBasepointSecret: privkeys[1],
		paymentBasepointSecret: privkeys[2],
		delayedPaymentBasepointSecret: privkeys[3],
		htlcBasepointSecret: privkeys[4],
		// The subject of these tests: simple taproot channels.
		preferTaproot: true
	};
}

/** Deterministic per-channel key deriver (unique keys per channel index). */
function makeChannelKeyDeriver(
	seedId: number
): (channelIndex: number) => IPerChannelKeys {
	return (channelIndex: number): IPerChannelKeys => {
		const seed = crypto
			.createHash('sha256')
			.update(makeSeed(seedId))
			.update(Buffer.from(`per-channel-${channelIndex}`))
			.digest();
		const privkeys = makePrivkeys(seed);
		return {
			fundingPrivkey: privkeys[0],
			basepoints: makeBasepoints(privkeys),
			perCommitmentSeed: crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from('pcs'))
				.digest(),
			revocationBasepointSecret: privkeys[1],
			paymentBasepointSecret: privkeys[2],
			delayedPaymentBasepointSecret: privkeys[3],
			htlcBasepointSecret: privkeys[4]
		};
	};
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): { channelId: Buffer; fundingTxid: Buffer } {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return { channelId, fundingTxid };
}

/** A valid but unknown-to-us per-commitment point. */
function makeForeignPoint(tag: string): Buffer {
	return perCommitmentPointFromSecret(
		crypto.createHash('sha256').update(Buffer.from(tag)).digest()
	);
}

/**
 * Assert the taproot to_remote sweep's shape and signature: spends the
 * commitment with a 1-block CSV, pays the destination minus the estimated fee,
 * and carries a valid BIP340 leaf signature for the given payment basepoint.
 */
function assertTaprootToRemoteSweep(
	sweep: bitcoin.Transaction,
	commitmentTxid: string,
	trackedAmount: bigint,
	paymentBasepoint: Buffer,
	destinationScript: Buffer,
	feeRatePerVbyte: number
): void {
	// Spends the commitment's to_remote outpoint with nSequence=1 (BIP68 1-CSV).
	expect(sweep.ins.length).to.equal(1);
	expect(Buffer.from(sweep.ins[0].hash).reverse().toString('hex')).to.equal(
		commitmentTxid
	);
	expect(sweep.ins[0].sequence).to.equal(1);

	// Pays the sweep destination, fee computed like every other recovery sweep.
	const feeSatoshis = BigInt(
		Math.ceil(feeRatePerVbyte * estimateSweepVbytes(OutputType.TO_REMOTE))
	);
	expect(sweep.outs.length).to.equal(1);
	expect(sweep.outs[0].script.equals(destinationScript)).to.equal(true);
	expect(BigInt(sweep.outs[0].value)).to.equal(trackedAmount - feeSatoshis);

	// Witness: [sig, leaf script, control block] for the 1-CSV to_remote leaf
	// paying OUR static payment basepoint under the NUMS internal key.
	const tr = buildTaprootToRemoteOutput(paymentBasepoint);
	const leaf = buildTaprootToRemoteScript(paymentBasepoint);
	const witness = sweep.ins[0].witness;
	expect(witness.length).to.equal(3);
	expect(Buffer.from(witness[1]).equals(leaf)).to.equal(true);
	expect(Buffer.from(witness[2]).equals(tr.spend.controlBlock)).to.equal(true);

	// The signature must verify against the leaf sighash and our x-only
	// payment basepoint - proving the private key the monitor supplied is the
	// one the on-chain output demands.
	const sighash = sweep.hashForWitnessV1(
		0,
		[tr.output],
		[Number(trackedAmount)],
		bitcoin.Transaction.SIGHASH_DEFAULT,
		tapleafHash(leaf, TAPLEAF_VERSION)
	);
	expect(
		verifyTaprootHtlcLeaf(sighash, toXOnly(paymentBasepoint), witness[0])
	).to.equal(true);
}

/**
 * Fake Electrum-style chain backend (mirrors scb-restore.test.ts): the funding
 * tx is "confirmed" at height 100 and the tip delivered via the headers
 * subscription is 200.
 */
class FakeChainBackend implements IChainBackend {
	transactions = new Map<string, Buffer>(); // display txid -> raw tx
	history = new Map<string, Array<{ txid: string; height: number }>>();
	subscribedScriptHashes: string[] = [];
	broadcasts: string[] = [];

	async subscribeToHeaders(
		onNewBlock: (height: number) => void
	): Promise<void> {
		onNewBlock(200);
	}

	async subscribeToScriptHash(scriptHash: string): Promise<void> {
		this.subscribedScriptHashes.push(scriptHash);
	}

	async getScriptHashHistory(
		scriptHash: string
	): Promise<Array<{ txid: string; height: number }>> {
		return this.history.get(scriptHash) ?? [];
	}

	async getTransaction(txid: string): Promise<Buffer> {
		const raw = this.transactions.get(txid);
		if (!raw) throw new Error(`Unknown tx ${txid}`);
		return raw;
	}

	async broadcastTransaction(rawTxHex: string): Promise<string> {
		this.broadcasts.push(rawTxHex);
		return bitcoin.Transaction.fromHex(rawTxHex).getId();
	}
}

/**
 * Build a live taproot channel between two fresh nodes, capture what recovery
 * needs, and tear the nodes down. The peer's commitment is fabricated from the
 * ORIGINAL state (foreign per-commitment point at a future index) - exactly
 * what the recovered side can never rebuild.
 */
function buildTaprootChannelFixture(
	pointTag: string,
	withChannelKeyDeriver = false
): {
	entries: IScbChannelEntry[];
	channelId: Buffer;
	state: IChannelState;
	commitmentTx: bitcoin.Transaction;
	paymentBasepoint: Buffer;
} {
	const aliceConfig = withChannelKeyDeriver
		? { ...makeNodeConfig(1), channelKeyDeriver: makeChannelKeyDeriver(1) }
		: makeNodeConfig(1);
	const alice = new LightningNode(aliceConfig);
	const bob = new LightningNode(makeNodeConfig(2));
	alice.on('node:error', () => {});
	bob.on('node:error', () => {});
	connectNodes(alice, bob);
	try {
		const { channelId } = openReadyChannel(alice, bob);
		const state = alice
			.getChannelManager()
			.getChannel(channelId)!
			.getFullState();
		expect(
			isTaprootChannel(state.channelType),
			'negotiated a taproot channel'
		).to.equal(true);
		const entries = alice.buildStaticChannelBackupData().channels;
		expect(entries).to.have.length(1);
		expect(entries[0].isTaproot).to.equal(true);
		const commitmentTx = buildRemoteCommitment(
			state,
			makeForeignPoint(pointTag),
			4n
		).result.tx;
		return {
			entries,
			channelId,
			state,
			commitmentTx,
			paymentBasepoint: state.localBasepoints.paymentBasepoint
		};
	} finally {
		alice.destroy();
		bob.destroy();
	}
}

describe('Taproot SCB-recovery sweep', function () {
	// ───────── resolver level: location + key derivation + construction ─────────

	describe('resolveTheirCurrentCommitmentOutputs - recovery state (taproot)', function () {
		it('locates and sweeps the to_remote leaf with no remote basepoints and no per-commitment point', function () {
			const { state, commitmentTx, paymentBasepoint } =
				buildTaprootChannelFixture('taproot-recovery-resolve');

			// Simulate the SCB-reconstructed state: no peer key material, no point
			// ever learned, broadcast-banned data-loss recovery.
			state.remoteBasepoints = null;
			state.remoteCurrentPerCommitmentPoint = null;
			state.dataLossDetected = true;

			// Classification: any non-coop funding spend is the peer's commitment.
			const classified = classifyCommitmentTx(commitmentTx, state);
			expect(classified.type).to.equal(CommitmentType.THEIR_FUTURE_COMMITMENT);

			// Output location: exactly our to_remote (NUMS internal key, 1-CSV leaf
			// paying our STATIC payment basepoint), matched with zero peer data.
			const tracked = classifyOutputs(
				commitmentTx,
				state,
				CommitmentType.THEIR_FUTURE_COMMITMENT,
				0n
			);
			expect(tracked.length).to.equal(1);
			expect(tracked[0].outputType).to.equal(OutputType.TO_REMOTE);
			const expectedSpk = buildTaprootToRemoteOutput(paymentBasepoint).output;
			expect(
				Buffer.from(commitmentTx.outs[tracked[0].outputIndex].script).equals(
					expectedSpk
				)
			).to.equal(true);

			// Resolution: the sweep must be produced WITHOUT any per-commitment
			// point (last arg undefined - the recovery state never has one).
			const destScript = bitcoin.payments.p2wpkh({
				pubkey: getPublicKey(makePrivkeys(makeSeed(9))[0]),
				network: bitcoin.networks.regtest
			}).output!;
			const feeRate = 10;
			const paymentBasepointSecret = makePrivkeys(makeSeed(1))[2];
			const resolved = resolveTheirCurrentCommitmentOutputs(
				state,
				tracked,
				destScript,
				feeRate,
				new Map(),
				paymentBasepointSecret,
				makePrivkeys(makeSeed(1))[4],
				undefined
			);
			expect(resolved.length).to.equal(1);
			expect(resolved[0].spendTx, 'a sweep transaction').to.not.be.undefined;
			expect(resolved[0].csvDelay).to.equal(1);

			const sweep = resolved[0].spendTx!;
			sweep.setWitness(0, resolved[0].witness!);
			assertTaprootToRemoteSweep(
				sweep,
				commitmentTx.getId(),
				tracked[0].amount,
				paymentBasepoint,
				destScript,
				feeRate
			);
		});

		it('drops non-to_remote outputs instead of refusing the sweep on a recovery state', function () {
			const { state, commitmentTx } = buildTaprootChannelFixture(
				'taproot-recovery-filter'
			);
			state.remoteBasepoints = null;
			state.remoteCurrentPerCommitmentPoint = null;
			state.dataLossDetected = true;

			const tracked = classifyOutputs(
				commitmentTx,
				state,
				CommitmentType.THEIR_FUTURE_COMMITMENT,
				0n
			);
			// Inject a bogus non-to_remote output alongside the real to_remote: the
			// resolver must still produce exactly the to_remote sweep.
			const resolved = resolveTheirCurrentCommitmentOutputs(
				state,
				[
					...tracked,
					{
						...tracked[0],
						outputIndex: tracked[0].outputIndex + 100,
						outputType: OutputType.RECEIVED_HTLC,
						paymentHash: Buffer.alloc(32)
					}
				],
				bitcoin.payments.p2wpkh({
					pubkey: getPublicKey(makePrivkeys(makeSeed(9))[0]),
					network: bitcoin.networks.regtest
				}).output!,
				10,
				new Map(),
				makePrivkeys(makeSeed(1))[2],
				makePrivkeys(makeSeed(1))[4],
				undefined
			);
			expect(resolved.length).to.equal(1);
			expect(resolved[0].trackedOutput.outputType).to.equal(
				OutputType.TO_REMOTE
			);
			expect(resolved[0].spendTx).to.not.be.undefined;
		});
	});

	// ───────── node level: recoverFromStaticChannelBackup end-to-end ─────────

	describe('LightningNode.recoverFromStaticChannelBackup - taproot channel', function () {
		/**
		 * Drive the full recovery flow against a fake chain backend and return
		 * the released sweep. The 1-CSV means the sweep is HELD when the peer's
		 * commitment confirms and released on the NEXT block - unlike the
		 * static_remotekey P2WPKH claim which broadcasts immediately.
		 */
		async function runRecovery(fixture: {
			entries: IScbChannelEntry[];
			channelId: Buffer;
			commitmentTx: bitcoin.Transaction;
			paymentBasepoint: Buffer;
			withChannelKeyDeriver?: boolean;
		}): Promise<void> {
			const { entries, channelId, commitmentTx, paymentBasepoint } = fixture;
			const backend = new FakeChainBackend();
			const fundingDisplayTxid = Buffer.from(entries[0].fundingTxid, 'hex')
				.reverse()
				.toString('hex');
			// Fabricated funding tx: only the watched output's script matters
			// (recovery takes it verbatim from the chain).
			const fundingTx = new bitcoin.Transaction();
			fundingTx.version = 2;
			fundingTx.addInput(crypto.randomBytes(32), 0);
			fundingTx.addOutput(
				bitcoin.payments.p2wsh({
					redeem: { output: bitcoin.script.compile([bitcoin.opcodes.OP_TRUE]) }
				}).output!,
				1_000_000
			);
			backend.transactions.set(fundingDisplayTxid, fundingTx.toBuffer());
			backend.transactions.set(commitmentTx.getId(), commitmentTx.toBuffer());
			backend.history.set(computeScriptHash(fundingTx.outs[0].script), [
				{ txid: fundingDisplayTxid, height: 100 }
			]);

			const storage = new SqliteStorage(':memory:');
			storage.open();
			const restoredConfig = fixture.withChannelKeyDeriver
				? {
						...makeNodeConfig(1),
						channelKeyDeriver: makeChannelKeyDeriver(1),
						storage,
						chainBackend: backend
				  }
				: { ...makeNodeConfig(1), storage, chainBackend: backend };
			const restored = new LightningNode(restoredConfig);
			restored.on('node:error', () => {});
			try {
				await restored.startChainWatcher();
				const result = await restored.recoverFromStaticChannelBackup(entries);
				expect(result.recovering).to.deep.equal([entries[0].channelId]);
				expect(result.skipped).to.deep.equal([]);

				const state = restored
					.getChannelManager()
					.getChannel(channelId)!
					.getFullState();
				expect(state.dataLossDetected).to.equal(true);
				expect(state.state).to.equal(ChannelState.ERRORED);
				expect(state.remoteBasepoints).to.equal(null);
				expect(isTaprootChannel(state.channelType)).to.equal(true);

				// The peer's commitment confirms at height 150: the to_remote is
				// tracked and its sweep is BUILT but HELD for the 1-block CSV (no
				// broadcast until maturity height 151).
				const destScript = restored.getSweepDestinationScript();
				const actions = restored
					.getChannelManager()
					.handleFundingSpent(channelId, commitmentTx, 150, destScript, 10);
				expect(
					actions.filter((a) => a.type === ChainActionType.BROADCAST_TX).length,
					'no premature (non-BIP68-final) broadcast'
				).to.equal(0);

				const monitor = restored.getChannelManager().getMonitor(channelId)!;
				const tracked = monitor.getTrackedOutputs();
				expect(tracked.length).to.equal(1);
				expect(tracked[0].outputType).to.equal(OutputType.TO_REMOTE);
				expect(tracked[0].status).to.equal(OutputStatus.CONFIRMED);
				expect(tracked[0].sweepTxHex, 'sweep built and held').to.not.be
					.undefined;
				expect(tracked[0].maturityHeight).to.equal(151);

				// Next block matures the CSV: the held sweep is released.
				const releaseActions = restored.getChannelManager().handleNewBlock(151);
				const broadcasts = releaseActions.filter(
					(a) => a.type === ChainActionType.BROADCAST_TX
				) as Array<{ tx: Buffer; description?: string }>;
				expect(broadcasts.length).to.equal(1);
				expect(broadcasts[0].description).to.contain('to_remote');

				const sweep = bitcoin.Transaction.fromBuffer(broadcasts[0].tx);
				assertTaprootToRemoteSweep(
					sweep,
					commitmentTx.getId(),
					tracked[0].amount,
					paymentBasepoint,
					destScript,
					10
				);
			} finally {
				restored.destroy();
				storage.close();
			}
		}

		it('sweeps the taproot to_remote after the 1-block CSV (node-level basepoints)', async function () {
			const fixture = buildTaprootChannelFixture('taproot-recovery-node');
			// Index 0 = node-level shared keys (no per-channel deriver).
			expect(fixture.entries[0].channelKeyIndex).to.equal(0);
			await runRecovery(fixture);
		});

		it('derives the to_remote key from the SCB channelKeyIndex (per-channel deriver keys)', async function () {
			const fixture = buildTaprootChannelFixture(
				'taproot-recovery-per-channel',
				true
			);
			// The entry's key locator is what recovery re-derives everything from
			// (per-channel indices start at 1; 0 means node-level shared keys).
			expect(fixture.entries[0].channelKeyIndex).to.equal(1);
			// Sanity: the channel's payment basepoint is the PER-CHANNEL one, not
			// the node-level basepoint - the sweep signature assertion inside
			// runRecovery therefore proves the per-channel secret was used.
			expect(
				fixture.paymentBasepoint.equals(
					makeBasepoints(makePrivkeys(makeSeed(1))).paymentBasepoint
				)
			).to.equal(false);
			expect(
				fixture.paymentBasepoint.equals(
					makeChannelKeyDeriver(1)(1).basepoints.paymentBasepoint
				)
			).to.equal(true);
			await runRecovery({ ...fixture, withChannelKeyDeriver: true });
		});
	});
});
