import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import type {
	IChannelAuxiliaryProvider,
	IAuxiliarySweepContext
} from '../../src/lightning/channel/auxiliary';
import {
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection
} from '../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	derivePublicKey,
	derivePrivateKey,
	deriveRevocationPubkey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput
} from '../../src/lightning/script/commitment-taproot';
import {
	classifyOutputs,
	resolveOurCommitmentOutputs,
	resolveTheirCurrentCommitmentOutputs,
	resolveSecondLevelHtlcOutput,
	resolveRevokedSecondLevelOutput
} from '../../src/lightning/chain/output-resolver';
import {
	ChainActionType,
	CommitmentType,
	MonitorState,
	OutputType,
	OutputStatus
} from '../../src/lightning/chain/types';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	serializeChainMonitorState,
	deserializeChainMonitorState
} from '../../src/lightning/storage/serialization';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';

bitcoin.initEccLib(ecc);
const priv = (n: number) => Buffer.alloc(32, n);
const pub = (n: number) => Buffer.from(ecc.pointFromScalar(priv(n), true)!);
const points = (n: number) => ({
	fundingPubkey: pub(n),
	revocationBasepoint: pub(n + 1),
	paymentBasepoint: pub(n + 2),
	delayedPaymentBasepoint: pub(n + 3),
	htlcBasepoint: pub(n + 4),
	firstPerCommitmentPoint: pub(n + 5)
});
const leaf = {
	script: bitcoin.script.compile([
		bitcoin.opcodes.OP_RETURN,
		Buffer.alloc(32, 42)
	]),
	leafVersion: 0xc0
};
const destination = bitcoin.payments.p2tr({
	internalPubkey: pub(20).subarray(1)
}).output!;
const assetDestination = bitcoin.payments.p2tr({
	internalPubkey: pub(20).subarray(1),
	scriptTree: { output: leaf.script }
}).output!;

function setup() {
	const state = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 1),
		fundingSatoshis: 200000n,
		pushMsat: 50000000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: points(1),
		localPerCommitmentSeed: priv(30)
	});
	state.remoteBasepoints = points(10);
	state.remoteConfig.toSelfDelay = 10;
	state.localConfig.toSelfDelay = 12;
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
	state.channelType = flags.toBuffer();
	const data = () => ({
		customData: Buffer.from('persisted commitment'),
		outputLeaves: new Map([[0, leaf]]),
		secondLevelLeaves: new Map([[`${HtlcDirection.RECEIVED}:7`, leaf]])
	});
	state.auxiliaryState = {
		channelData: Buffer.from('funded assets'),
		localBalance: 100n,
		remoteBalance: 0n,
		localCommitments: new Map([[0n, data()]]),
		remoteCommitments: new Map([[0n, data()]])
	};
	const seen: IAuxiliarySweepContext[] = [];
	const provider: IChannelAuxiliaryProvider = {
		buildCommitment: () => data(),
		signHtlcs: () => new Map(),
		verifyHtlcs: () => true,
		validateHtlc: () => undefined,
		getHtlcAmount: () => 0n,
		prepareShutdown: () => {
			throw new Error('shutdown is outside this recovery fixture');
		},
		verifyShutdown: () => false,
		buildClose: () => {
			throw new Error('close is outside this recovery fixture');
		},
		prepareSweep(context) {
			seen.push(context);
			const descriptor = context.inputs[0];
			const sigHash = Buffer.alloc(32, 23);
			const signature = context.sign({
				transactionInputIndex: 0,
				publicKey: descriptor.publicKey,
				sigHash
			});
			expect(
				ecc.verifySchnorr(sigHash, descriptor.publicKey.subarray(1), signature)
			).to.equal(true);
			return {
				outputScripts: new Map([[0, assetDestination]]),
				customData: Buffer.from('signed asset sweep')
			};
		}
	};
	state.auxiliaryProvider = provider;
	const point = perCommitmentPointFromSecret(
		generateFromSeed(state.localPerCommitmentSeed, MAX_INDEX)
	);
	const keys = {
		revocation: deriveRevocationPubkey(
			state.remoteBasepoints.revocationBasepoint,
			point
		),
		delayed: derivePublicKey(
			state.localBasepoints.delayedPaymentBasepoint,
			point
		)
	};
	return { state, seen, keys };
}
const txFor = (script: Buffer) => {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(Buffer.alloc(32, 3), 0);
	tx.addOutput(script, 100000);
	return tx;
};

describe('native auxiliary output recovery', () => {
	it('restores the commitment tree and signs Bitcoin only after preparing the asset output', () => {
		const { state, seen, keys } = setup();
		const tree = buildTaprootToLocalOutput(
			keys.revocation,
			keys.delayed,
			10,
			undefined,
			leaf
		);
		const tx = txFor(tree.output);
		const tracked = classifyOutputs(
			tx,
			state,
			CommitmentType.OUR_COMMITMENT,
			0n
		);
		expect(tracked).to.have.length(1);
		const [result] = resolveOurCommitmentOutputs(
			state,
			tracked,
			0n,
			destination,
			1,
			new Map(),
			priv(4)
		);
		expect(seen).to.have.length(1);
		expect(seen[0].inputs[0].kind).to.equal('to_local_delayed');
		expect(result.spendTx!.outs[0].script).to.deep.equal(assetDestination);
		expect(result.trackedOutput.auxiliaryData?.toString()).to.equal(
			'signed asset sweep'
		);
		expect(result.witness![2]).to.deep.equal(tree.delay.controlBlock);
		const hash = result.spendTx!.hashForWitnessV1(
			0,
			[tree.output],
			[100000],
			0,
			tapleafHash(tree.delay.script)
		);
		expect(
			ecc.verifySchnorr(hash, keys.delayed.subarray(1), result.witness![0])
		).to.equal(true);
	});

	it('archives Bitcoin-only companion sweeps in asset channels across replacement and restart', () => {
		const { state, keys, seen } = setup();
		state.auxiliaryState!.localCommitments.get(0n)!.outputLeaves.clear();
		const tree = buildTaprootToLocalOutput(keys.revocation, keys.delayed, 10),
			parent = txFor(tree.output);
		const tracked = classifyOutputs(
			parent,
			state,
			CommitmentType.OUR_COMMITMENT,
			0n
		);
		tracked[0].confirmationHeight = 100;
		const [resolved] = resolveOurCommitmentOutputs(
			state,
			tracked,
			0n,
			destination,
			1,
			new Map(),
			priv(4)
		);
		expect(seen).length(0);
		expect(resolved.auxiliaryData).equal(undefined);
		const initial = resolved.spendTx!;
		initial.setWitness(0, resolved.witness!);
		const output = resolved.trackedOutput;
		output.sweepTxHex = initial.toHex();
		output.status = OutputStatus.CONFIRMED;
		output.maturityHeight = 110;
		output.originalFeeRate = 1;
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.OUR_COMMITMENT,
					txid: parent.getId(),
					blockHeight: 100,
					commitmentNumber: 0n,
					trackedOutputs: [output]
				},
				trackedOutputs: [output],
				currentBlockHeight: 100
			},
			state,
			destination,
			1,
			priv(2),
			priv(3),
			undefined,
			priv(4),
			priv(5)
		);
		monitor.handleNewBlock(110);
		monitor.handleNewBlock(116);
		expect(
			monitor.rebuildSweep(monitor.getFullState().trackedOutputs[0], 2)
		).not.equal(null);
		const saved = deserializeChainMonitorState(
				serializeChainMonitorState(monitor.getFullState())
			),
			attempts = saved.trackedOutputs[0].auxiliarySweepAttempts!;
		expect(Object.keys(attempts).length).greaterThan(1);
		expect(attempts[initial.getId()].transaction).equal(initial.toHex());
		expect(attempts[initial.getId()].auxiliaryData).equal(undefined);
	});
	it('persists each signed RBF asset payload and selects an older confirmed winner after restore', () => {
		const { state, keys } = setup();
		const prepare = state.auxiliaryProvider!.prepareSweep!;
		state.auxiliaryProvider!.prepareSweep = (context) => ({
			...prepare(context),
			customData: Buffer.from(
				`asset sweep value ${context.transaction.outs[0].value}`
			)
		});
		const tree = buildTaprootToLocalOutput(
				keys.revocation,
				keys.delayed,
				10,
				undefined,
				leaf
			),
			parent = txFor(tree.output);
		const tracked = classifyOutputs(
			parent,
			state,
			CommitmentType.OUR_COMMITMENT,
			0n
		);
		tracked[0].confirmationHeight = 100;
		const [resolved] = resolveOurCommitmentOutputs(
			state,
			tracked,
			0n,
			destination,
			1,
			new Map(),
			priv(4)
		);
		const initial = resolved.spendTx!;
		initial.setWitness(0, resolved.witness!);
		const output = resolved.trackedOutput;
		output.sweepTxHex = initial.toHex();
		output.status = OutputStatus.CONFIRMED;
		output.maturityHeight = 110;
		output.originalFeeRate = 1;
		const originalData = Buffer.from(output.auxiliaryData!);
		const monitor = ChainMonitor.restore(
			{
				monitorState: MonitorState.RESOLVING,
				commitmentBroadcast: {
					commitmentType: CommitmentType.OUR_COMMITMENT,
					txid: parent.getId(),
					blockHeight: 100,
					commitmentNumber: 0n,
					trackedOutputs: [output]
				},
				trackedOutputs: [output],
				currentBlockHeight: 100
			},
			state,
			destination,
			1,
			priv(2),
			priv(3),
			undefined,
			priv(4),
			priv(5)
		);
		monitor.handleNewBlock(110);
		monitor.handleNewBlock(116);
		expect(
			monitor.rebuildSweep(monitor.getFullState().trackedOutputs[0], 2)
		).not.to.equal(null);
		const attempts =
			monitor.getFullState().trackedOutputs[0].auxiliarySweepAttempts!;
		expect(Object.keys(attempts).length).to.be.greaterThan(1);
		expect(attempts[initial.getId()].auxiliaryData).to.deep.equal(originalData);
		const current = monitor.getFullState().trackedOutputs[0];
		expect(current.auxiliaryData).not.to.deep.equal(originalData);
		const saved = deserializeChainMonitorState(
			serializeChainMonitorState(monitor.getFullState())
		);
		const restored = ChainMonitor.restore(
			saved,
			state,
			destination,
			1,
			priv(2),
			priv(3),
			undefined,
			priv(4),
			priv(5)
		);
		restored.handleOutputSpent(parent.getId(), 0, initial, 117);
		expect(restored.getFullState().trackedOutputs[0].resolutionTxid).to.equal(
			initial.getId()
		);
		expect(
			restored.getFullState().trackedOutputs[0].auxiliaryData
		).to.deep.equal(originalData);
		expect(
			restored.getFullState().trackedOutputs[0].auxiliarySweepAttempts
		).to.deep.equal(attempts);
	});

	for (const { fixed, assets } of [
		{ fixed: false, assets: true },
		{ fixed: true, assets: true },
		{ fixed: true, assets: false }
	])
		for (const offered of [false, true])
			it(`binds every funded ${offered ? 'timeout' : 'success'} output in ${
				fixed ? 'fixed' : 'compatibility'
			} mode for ${
				assets ? 'asset' : 'Bitcoin'
			} HTLCs and restores its exact payload`, () => {
				const { state, seen, keys } = setup(),
					tree = buildTaprootSecondLevelOutput(
						keys.revocation,
						keys.delayed,
						10,
						undefined,
						leaf
					);
				if (fixed) {
					const flags = FeatureFlags.fromBuffer(state.channelType!);
					flags.setCompulsory(Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS);
					state.channelType = flags.toBuffer();
				}
				const mode = fixed ? 0x81 : 0x83;
				const template = txFor(tree.output);
				const point = perCommitmentPointFromSecret(
					generateFromSeed(state.localPerCommitmentSeed, MAX_INDEX)
				);
				const localKey = derivePrivateKey(
					priv(5),
					point,
					state.localBasepoints.htlcBasepoint
				);
				const remoteKey = derivePrivateKey(
					priv(14),
					point,
					state.remoteBasepoints!.htlcBasepoint
				);
				const preimage = Buffer.alloc(32, 19);
				const paymentHash = bitcoin.crypto.sha256(preimage);
				const htlcTree = offered
					? buildTaprootOfferedHtlcOutput(
							keys.revocation,
							Buffer.from(ecc.pointFromScalar(localKey, true)!),
							Buffer.from(ecc.pointFromScalar(remoteKey, true)!),
							paymentHash,
							undefined,
							leaf
					  )
					: buildTaprootReceivedHtlcOutput(
							keys.revocation,
							Buffer.from(ecc.pointFromScalar(localKey, true)!),
							Buffer.from(ecc.pointFromScalar(remoteKey, true)!),
							paymentHash,
							500,
							undefined,
							leaf
					  );
				const spendLeaf = offered ? htlcTree.timeout : htlcTree.success;
				const digest = (
					transaction: bitcoin.Transaction,
					hashType: number,
					inputIndex = 0
				) =>
					transaction.hashForWitnessV1(
						inputIndex,
						transaction.ins.map((_, index) =>
							index === inputIndex ? htlcTree.output : Buffer.alloc(0)
						),
						transaction.ins.map((_, index) =>
							index === inputIndex ? 100000 : 0
						),
						hashType,
						tapleafHash(spendLeaf.script)
					);
				template.setWitness(0, [
					Buffer.concat([
						Buffer.from(ecc.signSchnorr(digest(template, mode), remoteKey)),
						Buffer.from([mode])
					]),
					Buffer.concat([
						Buffer.from(ecc.signSchnorr(digest(template, mode), localKey)),
						Buffer.from([mode])
					]),
					...(offered ? [] : [preimage]),
					spendLeaf.script,
					spendLeaf.controlBlock
				]);
				const payload = Buffer.from('persisted pre-signed asset child');
				const output = {
					txid: Buffer.from(template.ins[0].hash).reverse().toString('hex'),
					outputIndex: 0,
					amount: 100000n,
					witnessScript: htlcTree.output,
					paymentHash,
					outputType: offered
						? OutputType.OFFERED_HTLC
						: OutputType.RECEIVED_HTLC,
					status: OutputStatus.SPEND_BROADCAST,
					confirmationHeight: 100,
					sweepTxHex: template.toHex(),
					...(assets ? { auxiliaryData: payload } : {})
				};
				const monitor = ChainMonitor.restore(
					{
						monitorState: MonitorState.RESOLVING,
						currentBlockHeight: 100,
						trackedOutputs: [output],
						commitmentBroadcast: {
							commitmentType: CommitmentType.OUR_COMMITMENT,
							commitmentNumber: 0n,
							txid: output.txid,
							blockHeight: 100,
							trackedOutputs: [output]
						}
					},
					state,
					destination,
					1,
					priv(2),
					priv(3),
					undefined,
					priv(4),
					priv(5)
				);
				let funded = template.clone();
				funded.addInput(Buffer.alloc(32, 77), 0);
				if (!fixed)
					funded.addOutput(
						bitcoin.payments.p2wpkh({ pubkey: pub(20) }).output!,
						1000
					);
				const tracked = monitor.getTrackedOutputs()[0];
				const dispatch = (transaction: bitcoin.Transaction) =>
					(
						monitor as unknown as {
							_broadcastSweepAction(
								output: typeof tracked,
								tx: Buffer,
								description: string
							): import('../../src/lightning/chain/types').ChainAction;
						}
					)._broadcastSweepAction(
						tracked,
						transaction.toBuffer(),
						'asset HTLC fee attachment'
					);
				const action = dispatch(template);
				expect(action.type).equal(ChainActionType.FEE_BUMP_AND_BROADCAST);
				if (action.type !== ChainActionType.FEE_BUMP_AND_BROADCAST)
					throw new Error('Missing HTLC fee action');
				expect(action.fixedHtlcOutputs).equal(fixed);
				if (fixed) {
					expect(action.deferHtlcFunding!()).equal(true);
					const restoredPreparation = ChainMonitor.restore(
						deserializeChainMonitorState(
							serializeChainMonitorState(monitor.getFullState())
						),
						state,
						destination,
						1,
						priv(2),
						priv(3),
						undefined,
						priv(4),
						priv(5)
					);
					const retried = restoredPreparation
						.handleNewBlock(101)
						.find(
							(candidate) =>
								candidate.type === ChainActionType.FEE_BUMP_AND_BROADCAST
						);
					expect(retried?.type).equal(ChainActionType.FEE_BUMP_AND_BROADCAST);
					if (retried?.type !== ChainActionType.FEE_BUMP_AND_BROADCAST)
						throw new Error('Missing prepared fee retry');
					expect(retried.fixedHtlcOutputs).equal(true);
					expect(retried.feeratePerVbyte).equal(1);
				}

				expect(action.finalizeHtlcFunding).not.equal(undefined);
				expect(action.signHtlcFunding).not.equal(undefined);
				const corrupted = template.clone();
				corrupted.ins[0].witness = corrupted.ins[0].witness.map((item) =>
					Buffer.from(item)
				);
				corrupted.ins[0].witness[1][0] ^= 1;
				expect(() => dispatch(corrupted)).to.throw(
					'Original asset HTLC signature'
				);
				funded = bitcoin.Transaction.fromBuffer(
					action.signHtlcFunding!(funded.toBuffer())
				);
				expect(funded.ins[0].witness[0]).deep.equal(template.ins[0].witness[0]);
				expect(funded.ins[0].witness[1][64]).equal(0x81);
				const verify = (
					transaction: bitcoin.Transaction,
					index: number,
					key: Buffer,
					hashType: number,
					inputIndex = 0
				) =>
					ecc.verifySchnorr(
						digest(transaction, hashType, inputIndex),
						Buffer.from(ecc.pointFromScalar(key, true)!).subarray(1),
						transaction.ins[inputIndex].witness[index].subarray(0, 64)
					);
				expect(verify(funded, 0, remoteKey, mode)).equal(true);
				expect(verify(funded, 1, localKey, 0x81)).equal(true);
				const reordered = funded.clone();
				[reordered.ins[0], reordered.ins[1]] = [
					reordered.ins[1],
					reordered.ins[0]
				];
				const reorderedDigest = (hashType: number) =>
					reordered.hashForWitnessV1(
						1,
						[Buffer.alloc(0), htlcTree.output],
						[0, 100000],
						hashType,
						tapleafHash(spendLeaf.script)
					);
				expect(
					ecc.verifySchnorr(
						reorderedDigest(0x81),
						Buffer.from(ecc.pointFromScalar(localKey, true)!).subarray(1),
						reordered.ins[1].witness[1].subarray(0, 64)
					)
				).equal(true);
				expect(
					ecc.verifySchnorr(
						reorderedDigest(mode),
						Buffer.from(ecc.pointFromScalar(remoteKey, true)!).subarray(1),
						reordered.ins[1].witness[0].subarray(0, 64)
					)
				).equal(fixed);
				const wrongSignature = funded.clone();
				wrongSignature.ins[0].witness = wrongSignature.ins[0].witness.map(
					(item) => Buffer.from(item)
				);
				wrongSignature.ins[0].witness[1][0] ^= 1;
				expect(action.finalizeHtlcFunding!(wrongSignature.toBuffer())).equal(
					false
				);
				const stripped = funded.clone();
				stripped.ins.splice(1);
				expect(verify(stripped, 1, localKey, 0x81)).equal(true);
				stripped.addOutput(destination, 330);
				expect(verify(stripped, 0, remoteKey, mode)).equal(!fixed);
				expect(verify(stripped, 1, localKey, 0x81)).equal(false);
				expect(action.finalizeHtlcFunding!(stripped.toBuffer())).equal(false);
				const invalid = funded.clone();
				invalid.outs[0].value--;
				expect(action.finalizeHtlcFunding!(invalid.toBuffer())).equal(false);
				expect(action.finalizeHtlcFunding!(funded.toBuffer(), 4000n)).equal(
					true
				);
				expect(dispatch(funded).type).equal(ChainActionType.BROADCAST_TX);
				expect(tracked.auxiliarySweepFee).equal(4000n);
				expect(
					tracked.auxiliarySweepAttempts![funded.getId()].auxiliarySweepFee
				).equal(4000n);
				expect(action.finalizeHtlcFunding!(funded.toBuffer())).equal(false);
				expect(
					monitor.getFullState().trackedOutputs[0].auxiliaryHtlcFeeFunded
				).equal(true);
				const pending = deserializeChainMonitorState(
					serializeChainMonitorState(monitor.getFullState())
				);
				pending.trackedOutputs[0].auxiliaryHtlcFeeFunded = false;
				pending.trackedOutputs[0].sweepTxHex = template.toHex();
				const replacing = ChainMonitor.restore(
					pending,
					state,
					destination,
					2,
					priv(2),
					priv(3),
					undefined,
					priv(4),
					priv(5)
				);
				const replacement = (
					replacing as unknown as {
						_broadcastSweepAction(
							output: typeof tracked,
							transaction: Buffer,
							description: string
						): import('../../src/lightning/chain/types').ChainAction;
					}
				)._broadcastSweepAction(
					replacing.getTrackedOutputs()[0],
					template.toBuffer(),
					'replacement'
				);
				if (replacement.type !== ChainActionType.FEE_BUMP_AND_BROADCAST)
					throw new Error('Missing replacement context');
				expect(replacement.conflictingCandidateTxids).include(funded.getId());
				expect(replacement.previousFundedTransaction).deep.equal(
					funded.toBuffer()
				);
				expect(replacement.previousFee).equal(4000n);
				let bumped = template.clone();
				bumped.addInput(Buffer.alloc(32, 78), 0);
				if (!fixed) bumped.addOutput(funded.outs[1].script, 500);
				bumped = bitcoin.Transaction.fromBuffer(
					replacement.signHtlcFunding!(bumped.toBuffer())
				);
				expect(verify(bumped, 1, localKey, 0x81)).equal(true);
				expect(
					replacement.finalizeHtlcFunding!(bumped.toBuffer(), 4500n)
				).equal(true);
				// A third party can replace only external fee inputs without knowing our key.
				const external = funded.clone();
				external.ins[1].hash = Buffer.alloc(32, 79);
				if (fixed)
					[external.ins[0], external.ins[1]] = [
						external.ins[1],
						external.ins[0]
					];
				expect(verify(external, 1, localKey, 0x81, fixed ? 1 : 0)).equal(true);
				const altered = external.clone();
				altered.addOutput(destination, 330);
				const rejected = ChainMonitor.restore(
					deserializeChainMonitorState(
						serializeChainMonitorState(replacing.getFullState())
					),
					state,
					destination,
					2,
					priv(2),
					priv(3),
					undefined,
					priv(4),
					priv(5)
				);
				rejected.handleOutputSpent(output.txid, 0, altered, 101);
				expect(
					rejected.getTrackedOutputs()[0].auxiliarySweepAttempts![
						altered.getId()
					]
				).equal(undefined);
				expect(
					rejected.getTrackedOutputs().some((item) => item.isSecondLevelHtlc)
				).equal(false);
				const resumed = ChainMonitor.restore(
					deserializeChainMonitorState(
						serializeChainMonitorState(replacing.getFullState())
					),
					state,
					destination,
					2,
					priv(2),
					priv(3),
					undefined,
					priv(4),
					priv(5)
				);
				resumed.handleOutputSpent(output.txid, 0, external, 101);
				const restored = deserializeChainMonitorState(
					serializeChainMonitorState(resumed.getFullState())
				);
				expect(
					restored.trackedOutputs[0].auxiliarySweepAttempts![external.getId()]
						.transaction
				).to.equal(external.toHex());
				expect(restored.trackedOutputs[0].sweepTxHex).equal(external.toHex());
				expect(
					restored.trackedOutputs[0].auxiliarySweepAttempts![external.getId()]
						.auxiliaryHtlcFeeFunded
				).equal(true);
				expect(
					restored.trackedOutputs[0].auxiliarySweepAttempts![external.getId()]
						.auxiliaryData
				).to.deep.equal(assets ? payload : undefined);
				expect(
					restored.trackedOutputs.some(
						(item) => item.txid === external.getId() && item.isSecondLevelHtlc
					)
				).to.equal(true);
				expect(seen[0].inputs[0].previousAuxiliaryData).to.deep.equal(
					assets ? payload : undefined
				);
			});

	it('refuses asset-burning fallback and unrelated signing requests', () => {
		const { state, keys } = setup();
		const tree = buildTaprootToLocalOutput(
			keys.revocation,
			keys.delayed,
			10,
			undefined,
			leaf
		);
		const tracked = classifyOutputs(
			txFor(tree.output),
			state,
			CommitmentType.OUR_COMMITMENT,
			0n
		);
		state.auxiliaryProvider!.prepareSweep = undefined;
		expect(() =>
			resolveOurCommitmentOutputs(
				state,
				tracked,
				0n,
				destination,
				1,
				new Map(),
				priv(4)
			)
		).to.throw('Asset sweep provider is required');
		state.auxiliaryProvider!.prepareSweep = (context) => {
			context.sign({
				transactionInputIndex: 0,
				publicKey: pub(9),
				sigHash: Buffer.alloc(32)
			});
			throw new Error('not reached');
		};
		expect(() =>
			resolveOurCommitmentOutputs(
				state,
				tracked,
				0n,
				destination,
				1,
				new Map(),
				priv(4)
			)
		).to.throw('unrelated signing key');
	});
	it('recovers the indexed second-level tree and persists its exact HTLC identity', () => {
		const { state, seen, keys } = setup();
		const tree = buildTaprootSecondLevelOutput(
			keys.revocation,
			keys.delayed,
			10,
			undefined,
			leaf
		);
		const result = resolveSecondLevelHtlcOutput(
			state,
			txFor(tree.output),
			100,
			0n,
			destination,
			1,
			priv(4)
		)!;
		expect(result.trackedOutput.htlcId).to.equal(7n);
		expect(result.trackedOutput.auxiliaryHtlcDirection).to.equal(
			HtlcDirection.RECEIVED
		);
		expect(seen[0].inputs[0].kind).to.equal('second_level_delayed');
		expect(result.witness![2]).to.deep.equal(tree.delay.controlBlock);
		expect(result.spendTx!.outs[0].script).to.deep.equal(assetDestination);
	});
	it('funds a dust-sized asset second level after restart without mutating its payload before finalize', () => {
		const { state, keys } = setup();
		const tree = buildTaprootSecondLevelOutput(
			keys.revocation,
			keys.delayed,
			10,
			undefined,
			leaf
		);
		const child = txFor(tree.output);
		child.outs[0].value = 355;
		const parentData = Buffer.from('parent asset transition');
		const claim = resolveSecondLevelHtlcOutput(
			state,
			child,
			100,
			0n,
			destination,
			10,
			priv(4),
			undefined,
			parentData
		)!;
		expect(claim.declinedAsUneconomic).not.equal(true);
		expect(claim.auxiliaryFunding).not.equal(undefined);
		claim.spendTx!.setWitness(0, claim.witness!);
		claim.trackedOutput.sweepTxHex = claim.spendTx!.toHex();
		claim.trackedOutput.maturityHeight = 110;
		const monitor = ChainMonitor.restore(
			deserializeChainMonitorState(
				serializeChainMonitorState({
					monitorState: MonitorState.RESOLVING,
					commitmentBroadcast: {
						commitmentType: CommitmentType.OUR_COMMITMENT,
						txid: Buffer.alloc(32, 19).toString('hex'),
						blockHeight: 90,
						commitmentNumber: 0n,
						trackedOutputs: [claim.trackedOutput]
					},
					trackedOutputs: [claim.trackedOutput],
					currentBlockHeight: 100
				})
			),
			state,
			destination,
			10,
			priv(2),
			priv(3),
			undefined,
			priv(4),
			priv(5)
		);
		const action = monitor
			.handleNewBlock(111)
			.find(
				(candidate) =>
					candidate.type === ChainActionType.FEE_BUMP_AND_BROADCAST &&
					candidate.kind === 'auxiliary-sweep-fee-attach'
			);
		if (!action || action.type !== ChainActionType.FEE_BUMP_AND_BROADCAST)
			throw new Error('Missing asset sweep fee action');
		const before = Buffer.from(
			monitor.getFullState().trackedOutputs[0].auxiliaryData!
		);
		const funded = bitcoin.Transaction.fromBuffer(action.tx);
		funded.addInput(Buffer.alloc(32, 21), 0, 0xfffffffd);
		const feeScript = bitcoin.payments.p2wpkh({ pubkey: pub(21) }).output!;
		funded.addOutput(feeScript, 9000);
		const signed = action.auxiliarySweep!.sign(
			funded.toBuffer(),
			[tree.output, feeScript],
			[355n, 10000n]
		);
		expect(monitor.getFullState().trackedOutputs[0].auxiliaryData).deep.equal(
			before
		);
		const final = bitcoin.Transaction.fromBuffer(signed.transaction);
		const digest = final.hashForWitnessV1(
			0,
			[tree.output, feeScript],
			[355, 10000],
			bitcoin.Transaction.SIGHASH_DEFAULT,
			tapleafHash(tree.delay.script, tree.delay.leafVersion)
		);
		expect(
			ecc.verifySchnorr(
				digest,
				keys.delayed.subarray(1),
				final.ins[0].witness[0]
			)
		).equal(true);
		expect(
			action.auxiliarySweep!.finalize(
				signed.transaction,
				signed.auxiliaryData,
				1000n
			)
		).equal(true);
		const stored = monitor.getFullState().trackedOutputs[0];
		expect(stored.auxiliarySweepAttempts![final.getId()].transaction).equal(
			final.toHex()
		);
		expect(stored.auxiliaryParentData).deep.equal(parentData);
		expect(stored.auxiliaryFeeFunded).equal(true);
		expect(stored.auxiliarySweepFee).equal(1000n);
		expect(
			stored.auxiliarySweepAttempts![final.getId()].auxiliarySweepFee
		).equal(1000n);
		const retry = (
			monitor as unknown as {
				_broadcastSweepAction(
					output: typeof stored,
					tx: Buffer,
					description: string
				): {
					type: ChainActionType;
					tx: Buffer;
					requiresMonitorPersistence?: boolean;
				};
			}
		)._broadcastSweepAction(stored, final.toBuffer(), 'retry');
		expect(retry.type).equal(ChainActionType.BROADCAST_TX);
		expect(retry.tx).deep.equal(final.toBuffer());
		expect(retry.requiresMonitorPersistence).equal(true);
		const replacement = monitor.rebuildSweepActions(stored, 11)[0];
		expect(replacement.type).equal(ChainActionType.FEE_BUMP_AND_BROADCAST);
		if (replacement.type === ChainActionType.FEE_BUMP_AND_BROADCAST)
			expect(replacement.auxiliarySweep!.previousFee).equal(1000n);

		expect(
			action.auxiliarySweep!.finalize(signed.transaction, signed.auxiliaryData)
		).equal(false);
		stored.auxiliarySweepFee = 3000n;
		monitor.handleOutputSpent(stored.txid, stored.outputIndex, final, 118);
		expect(stored.auxiliarySweepFee).equal(1000n);
		expect(stored.auxiliaryFeeFunded).equal(true);
	});

	for (const kind of ['local', 'remote', 'success', 'timeout'] as const)
		it(`funds a small direct ${kind} asset claim and signs every prevout`, () => {
			const { state, keys } = setup(),
				point = pub(15),
				preimage = Buffer.alloc(32, 77),
				paymentHash = bitcoin.crypto.sha256(preimage);
			const revocation = deriveRevocationPubkey(
					state.localBasepoints.revocationBasepoint,
					point
				),
				holderHtlc = derivePublicKey(
					state.remoteBasepoints!.htlcBasepoint,
					point
				),
				ourHtlc = derivePublicKey(state.localBasepoints.htlcBasepoint, point);
			const ownTree = buildTaprootToLocalOutput(
					keys.revocation,
					keys.delayed,
					10,
					undefined,
					leaf
				),
				remoteTree = buildTaprootToRemoteOutput(pub(3), undefined, leaf),
				successTree = buildTaprootOfferedHtlcOutput(
					revocation,
					holderHtlc,
					ourHtlc,
					paymentHash,
					undefined,
					leaf
				),
				timeoutTree = buildTaprootReceivedHtlcOutput(
					revocation,
					holderHtlc,
					ourHtlc,
					paymentHash,
					500,
					undefined,
					leaf
				);
			const tree =
				kind === 'local'
					? ownTree
					: kind === 'remote'
					? remoteTree
					: kind === 'success'
					? successTree
					: timeoutTree;
			const spendLeaf =
				kind === 'local'
					? ownTree.delay
					: kind === 'remote'
					? remoteTree.spend
					: kind === 'success'
					? successTree.success
					: timeoutTree.timeout;
			const parent = txFor(tree.output);
			parent.outs[0].value = 355;
			const output = {
				txid: parent.getId(),
				outputIndex: 0,
				amount: 355n,
				outputType:
					kind === 'local'
						? OutputType.TO_LOCAL
						: kind === 'remote'
						? OutputType.TO_REMOTE
						: kind === 'success'
						? OutputType.RECEIVED_HTLC
						: OutputType.OFFERED_HTLC,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 100,
				auxiliaryCommitmentNumber: 0n,
				htlcId: 7n,
				paymentHash,
				cltvExpiry: 500
			};
			const result =
				kind === 'local'
					? resolveOurCommitmentOutputs(
							state,
							[output],
							0n,
							destination,
							10,
							new Map(),
							priv(4)
					  )[0]
					: resolveTheirCurrentCommitmentOutputs(
							state,
							[output],
							destination,
							10,
							new Map([[paymentHash.toString('hex'), preimage]]),
							priv(3),
							priv(5),
							point
					  )[0];
			expect(result.auxiliaryFunding).not.equal(undefined);
			expect(result.declinedAsUneconomic).not.equal(true);
			const before = Buffer.from(result.trackedOutput.auxiliaryData!),
				funded = result.spendTx!.clone(),
				feeScript = bitcoin.payments.p2wpkh({ pubkey: pub(21) }).output!;
			funded.addInput(Buffer.alloc(32, 21), 0, 0xfffffffd);
			funded.addOutput(feeScript, 7000);
			const signed = result.auxiliaryFunding!.sign(
					funded.toBuffer(),
					[tree.output, feeScript],
					[355n, 10000n]
				),
				final = bitcoin.Transaction.fromBuffer(signed.transaction);
			expect(result.trackedOutput.auxiliaryData).deep.equal(before);
			expect(final.outs[0].value).equal(355);
			expect(final.outs[0].script).deep.equal(assetDestination);
			const hash = final.hashForWitnessV1(
					0,
					[tree.output, feeScript],
					[355, 10000],
					bitcoin.Transaction.SIGHASH_DEFAULT,
					tapleafHash(spendLeaf.script, spendLeaf.leafVersion)
				),
				key =
					kind === 'local'
						? keys.delayed
						: kind === 'remote'
						? pub(3)
						: ourHtlc;
			expect(
				ecc.verifySchnorr(hash, key.subarray(1), final.ins[0].witness[0])
			).equal(true);
			if (kind === 'success')
				expect(final.ins[0].witness[1]).deep.equal(preimage);
			expect(() =>
				result.auxiliaryFunding!.sign(funded.toBuffer(), [tree.output], [355n])
			).to.throw('prevouts');
		});

	it('uses the full auxiliary tree root for revoked second-level key-path justice', () => {
		const { state, seen } = setup();
		const secret = priv(31);
		state.shaChainStore.addSecret(MAX_INDEX, secret);
		const point = perCommitmentPointFromSecret(secret);
		const revocation = deriveRevocationPubkey(
			state.localBasepoints.revocationBasepoint,
			point
		);
		const delayed = derivePublicKey(
			state.remoteBasepoints!.delayedPaymentBasepoint,
			point
		);
		const tree = buildTaprootSecondLevelOutput(
			revocation,
			delayed,
			12,
			undefined,
			leaf
		);
		const [result] = resolveRevokedSecondLevelOutput(
			state,
			txFor(tree.output),
			100,
			0n,
			destination,
			1,
			priv(2)
		);
		expect(seen[0].inputs[0].kind).to.equal('second_level_revocation');
		expect(result.trackedOutput.htlcId).to.equal(7n);
		const hash = result.spendTx!.hashForWitnessV1(
			0,
			[tree.output],
			[100000],
			0
		);
		expect(
			ecc.verifySchnorr(hash, tree.outputKey, result.witness![0])
		).to.equal(true);
	});
});
