import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import type {
	IChannelAuxiliaryProvider,
	IAuxiliaryCommitmentData
} from '../../src/lightning/channel/auxiliary';
import {
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection
} from '../../src/lightning/channel/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	derivePublicKey,
	deriveRevocationPubkey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import {
	buildTaprootToLocalOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootSecondLevelOutput
} from '../../src/lightning/script/commitment-taproot';
import { calculateObscuredCommitmentNumber } from '../../src/lightning/script/commitment';
import {
	resolveRevokedCommitmentOutputs,
	resolveRevokedSecondLevelOutput
} from '../../src/lightning/chain/output-resolver';
import {
	ChainActionType,
	CommitmentType,
	MonitorState,
	OutputType,
	OutputStatus,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	serializeChainMonitorState,
	deserializeChainMonitorState
} from '../../src/lightning/storage/serialization';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
import {
	buildAuxiliaryJusticePackage,
	validateAuxiliaryJusticePackage
} from '../../src/lightning/watchtower/auxiliary';

bitcoin.initEccLib(ecc);
const priv = (n: number): Buffer => Buffer.alloc(32, n);
const pub = (n: number): Buffer =>
	Buffer.from(ecc.pointFromScalar(priv(n), true)!);
const points = (
	n: number
): ReturnType<typeof createOpenerState>['localBasepoints'] => ({
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
const feeScript = bitcoin.payments.p2wpkh({ pubkey: pub(21) }).output!;

function setup(): {
	state: ReturnType<typeof createOpenerState>;
	parent: bitcoin.Transaction;
	outputs: ITrackedOutput[];
	local: ReturnType<typeof buildTaprootToLocalOutput>;
	htlc: ReturnType<typeof buildTaprootOfferedHtlcOutput>;
	revocation: Buffer;
	delayed: Buffer;
} {
	const state = createOpenerState({
		temporaryChannelId: priv(1),
		fundingSatoshis: 200000n,
		pushMsat: 50000000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: points(1),
		localPerCommitmentSeed: priv(30)
	});
	state.channelId = priv(9);
	state.remoteBasepoints = points(10);
	state.localConfig.toSelfDelay = 12;
	state.fundingTxid = priv(3);
	state.fundingOutputIndex = 0;
	state.remoteCommitmentNumber = 1n;
	state.shaChainStore.addSecret(MAX_INDEX, priv(31));
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
	state.channelType = flags.toBuffer();
	const data = (): IAuxiliaryCommitmentData => ({
		customData: Buffer.from('persisted asset commitment'),
		outputLeaves: new Map([
			[0, leaf],
			[1, leaf]
		]),
		secondLevelLeaves: new Map([[`${HtlcDirection.RECEIVED}:7`, leaf]]),
		htlcOutputIndexes: new Map([[`${HtlcDirection.RECEIVED}:7`, 1]])
	});
	state.auxiliaryState = {
		channelData: Buffer.from('funded assets'),
		localBalance: 100n,
		remoteBalance: 0n,
		localCommitments: new Map(),
		remoteCommitments: new Map([[0n, data()]])
	};
	let counter = 0;
	const provider: IChannelAuxiliaryProvider = {
		buildCommitment: data,
		signHtlcs: () => new Map(),
		verifyHtlcs: () => true,
		validateHtlc: () => undefined,
		getHtlcAmount: () => 0n,
		prepareShutdown: () => {
			throw Error('unused');
		},
		verifyShutdown: () => false,
		buildClose: () => {
			throw Error('unused');
		},
		prepareSweep(context) {
			for (const input of context.inputs) {
				const digest = priv(23),
					signature = context.sign({
						transactionInputIndex: input.transactionInputIndex,
						publicKey: input.publicKey,
						sigHash: digest
					});
				expect(
					ecc.verifySchnorr(digest, input.publicKey.subarray(1), signature)
				).equal(true);
			}
			return {
				outputScripts: new Map([[0, assetDestination]]),
				customData: Buffer.from(`signed asset transition ${++counter}`)
			};
		}
	};
	state.auxiliaryProvider = provider;
	const point = perCommitmentPointFromSecret(priv(31)),
		revocation = deriveRevocationPubkey(
			state.localBasepoints.revocationBasepoint,
			point
		),
		delayed = derivePublicKey(
			state.remoteBasepoints.delayedPaymentBasepoint,
			point
		),
		paymentHash = priv(44);
	const local = buildTaprootToLocalOutput(
		revocation,
		delayed,
		12,
		undefined,
		leaf
	);
	const htlc = buildTaprootOfferedHtlcOutput(
		revocation,
		derivePublicKey(state.remoteBasepoints.htlcBasepoint, point),
		derivePublicKey(state.localBasepoints.htlcBasepoint, point),
		paymentHash,
		undefined,
		leaf
	);
	const parent = new bitcoin.Transaction();
	parent.version = 2;
	parent.addInput(priv(3), 0);
	parent.addOutput(local.output, 355);
	parent.addOutput(htlc.output, 355);
	const obscured = calculateObscuredCommitmentNumber(
		state.localBasepoints.paymentBasepoint,
		state.remoteBasepoints.paymentBasepoint,
		0n
	);
	parent.locktime = 0x20000000 | Number(obscured & 0xffffffn);
	parent.ins[0].sequence = (0x80000000 | Number(obscured >> 24n)) >>> 0;
	state.revokedHtlcSnapshots = new Map([
		[
			'0',
			[
				{
					id: 7n,
					direction: HtlcDirection.RECEIVED,
					paymentHash,
					amountMsat: 355000n,
					cltvExpiry: 500,
					auxiliaryAmount: 100n
				}
			]
		]
	]);
	const outputs: ITrackedOutput[] = [0, 1].map((index) => ({
		txid: parent.getId(),
		outputIndex: index,
		amount: 355n,
		outputType: index === 0 ? OutputType.TO_LOCAL : OutputType.RECEIVED_HTLC,
		status: OutputStatus.CONFIRMED,
		confirmationHeight: 100,
		auxiliaryCommitmentNumber: 0n,
		...(index === 1
			? {
					paymentHash,
					cltvExpiry: 500,
					htlcId: 7n,
					auxiliaryHtlcDirection: HtlcDirection.RECEIVED
			  }
			: {})
	}));
	return { state, parent, outputs, local, htlc, revocation, delayed };
}

function funded(raw: Buffer): bitcoin.Transaction {
	const tx = bitcoin.Transaction.fromBuffer(raw);
	tx.addInput(priv(21), 0, 0xfffffffd);
	tx.addOutput(feeScript, 7000);
	return tx;
}

describe('fee-sponsored asset penalties', () => {
	it('re-signs every aggregate input and commits all monitor rows atomically after restart', () => {
		const f = setup();
		const monitor = new ChainMonitor(
			f.state,
			destination,
			10,
			priv(2),
			priv(3),
			undefined,
			priv(4),
			priv(5)
		);
		const actions = monitor.handleFundingSpent(f.parent, 100);
		const action = actions.find(
			(a) => a.type === ChainActionType.FEE_BUMP_AND_BROADCAST
		);
		expect(action, 'sponsored aggregate').not.equal(undefined);
		if (!action || action.type !== ChainActionType.FEE_BUMP_AND_BROADCAST)
			throw Error('missing action');
		expect(
			actions.filter((a) => a.type === ChainActionType.FEE_BUMP_AND_BROADCAST)
		).length(1);
		expect(bitcoin.Transaction.fromBuffer(action.tx).ins).length(2);
		const restored = ChainMonitor.restore(
			deserializeChainMonitorState(
				serializeChainMonitorState(monitor.getFullState())
			),
			f.state,
			destination,
			10,
			priv(2),
			priv(3),
			undefined,
			priv(4),
			priv(5)
		);
		const retry = restored
			.rebuildSweepActions(restored.getTrackedOutputs()[0], 10)
			.find((a) => a.type === ChainActionType.FEE_BUMP_AND_BROADCAST);
		if (!retry || retry.type !== ChainActionType.FEE_BUMP_AND_BROADCAST)
			throw Error('missing restored action');
		const before = restored
			.getFullState()
			.trackedOutputs.map((o) => o.auxiliaryData?.toString('hex'));
		const tx = funded(retry.tx),
			scripts = [f.local.output, f.htlc.output, feeScript],
			values = [355n, 355n, 10000n];
		const signed = retry.auxiliarySweep!.sign(tx.toBuffer(), scripts, values),
			final = bitcoin.Transaction.fromBuffer(signed.transaction);
		expect(
			restored
				.getFullState()
				.trackedOutputs.map((o) => o.auxiliaryData?.toString('hex'))
		).deep.equal(before);
		expect(final.outs[0].value).equal(710);
		expect(final.outs[0].script).deep.equal(assetDestination);
		expect(
			ecc.verifySchnorr(
				final.hashForWitnessV1(
					0,
					scripts,
					values.map(Number),
					0,
					tapleafHash(f.local.revoke.script)
				),
				f.revocation.subarray(1),
				final.ins[0].witness[0]
			)
		).equal(true);
		expect(
			ecc.verifySchnorr(
				final.hashForWitnessV1(1, scripts, values.map(Number), 0),
				f.htlc.outputKey,
				final.ins[1].witness[0]
			)
		).equal(true);
		expect(
			retry.auxiliarySweep!.finalize(
				signed.transaction,
				signed.auxiliaryData,
				3000n
			)
		).equal(true);
		for (const output of restored.getFullState().trackedOutputs) {
			expect(output.sweepTxHex).equal(final.toHex());
			expect(output.auxiliaryData).deep.equal(signed.auxiliaryData);
			expect(
				output.auxiliarySweepAttempts![final.getId()].auxiliaryData
			).deep.equal(signed.auxiliaryData);
		}
		expect(
			retry.auxiliarySweep!.finalize(signed.transaction, signed.auxiliaryData)
		).equal(false);
		const replacement = restored
			.rebuildSweepActions(restored.getTrackedOutputs()[0], 11)
			.find((a) => a.type === ChainActionType.FEE_BUMP_AND_BROADCAST);
		if (
			!replacement ||
			replacement.type !== ChainActionType.FEE_BUMP_AND_BROADCAST
		)
			throw Error('missing replacement');
		expect(replacement.conflictingCandidateTxids).include(final.getId());
		expect(replacement.previousFundedTransaction).deep.equal(final.toBuffer());
		expect(replacement.previousFee).equal(3000n);
	});
	it('retains replacement conflicts and fees without excluding confirmed parent change', () => {
		const f = setup(),
			tree = buildTaprootSecondLevelOutput(
				f.revocation,
				f.delayed,
				12,
				undefined,
				leaf
			),
			parent = new bitcoin.Transaction();
		parent.version = 2;
		parent.addInput(f.parent.getHash(), 1);
		parent.addInput(priv(22), 0);
		parent.addOutput(tree.output, 355);
		parent.addOutput(feeScript, 1000);
		const [claim] = resolveRevokedSecondLevelOutput(
			f.state,
			parent,
			101,
			0n,
			destination,
			10,
			priv(2)
		);
		const scripts = [tree.output, feeScript],
			values = [355n, 10000n];
		const first = claim.auxiliaryFunding!.sign(
			funded(claim.spendTx!.toBuffer()).toBuffer(),
			scripts,
			values
		);
		const higher = bitcoin.Transaction.fromBuffer(first.transaction);
		higher.outs[1].value = 6000;
		const older = claim.auxiliaryFunding!.sign(
			higher.toBuffer(),
			scripts,
			values
		);
		const firstTx = bitcoin.Transaction.fromBuffer(first.transaction),
			olderTx = bitcoin.Transaction.fromBuffer(older.transaction);
		const parentRow: ITrackedOutput = {
			...f.outputs[1],
			status: OutputStatus.SPEND_CONFIRMED,
			sweepTxHex: parent.toHex(),
			auxiliaryData: Buffer.from('parent'),
			auxiliaryHtlcFeeFunded: true,
			auxiliarySweepFee: 9000n,
			auxiliarySweepAttempts: {
				[parent.getId()]: {
					transaction: parent.toHex(),
					auxiliaryData: Buffer.from('parent'),
					auxiliaryHtlcFeeFunded: true,
					auxiliarySweepFee: 9000n
				}
			}
		};
		const childRow: ITrackedOutput = {
			...claim.trackedOutput,
			secondLevelTxHex: parent.toHex(),
			sweepTxHex: firstTx.toHex(),
			auxiliaryData: first.auxiliaryData,
			auxiliaryFeeFunding: true,
			auxiliaryFeeFunded: true,
			auxiliarySweepFee: 3000n,
			auxiliarySweepAttempts: {
				[olderTx.getId()]: {
					transaction: olderTx.toHex(),
					auxiliaryData: older.auxiliaryData,
					auxiliaryFeeFunded: true,
					auxiliarySweepFee: 4000n
				},
				[firstTx.getId()]: {
					transaction: firstTx.toHex(),
					auxiliaryData: first.auxiliaryData,
					auxiliaryFeeFunded: true,
					auxiliarySweepFee: 3000n
				}
			}
		};
		const rows = [parentRow, childRow],
			monitor = ChainMonitor.restore(
				deserializeChainMonitorState(
					serializeChainMonitorState({
						monitorState: MonitorState.RESOLVING,
						commitmentBroadcast: {
							commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT,
							txid: f.parent.getId(),
							blockHeight: 100,
							commitmentNumber: 0n,
							trackedOutputs: rows,
							revokedTxHex: f.parent.toHex()
						},
						trackedOutputs: rows,
						currentBlockHeight: 102
					})
				),
				f.state,
				destination,
				10,
				priv(2),
				priv(3)
			);
		const child = monitor
			.getTrackedOutputs()
			.find((row) => row.txid === parent.getId())!;
		const action = monitor
			.rebuildSweepActions(child, 11)
			.find((a) => a.type === ChainActionType.FEE_BUMP_AND_BROADCAST);
		if (!action || action.type !== ChainActionType.FEE_BUMP_AND_BROADCAST)
			throw Error('missing child action');
		expect(action.conflictingCandidateTxids)
			.include(firstTx.getId())
			.and.include(olderTx.getId());
		expect(action.conflictingCandidateTxids).not.include(parent.getId());
		expect(action.previousFundedTransaction).deep.equal(older.transaction);
		expect(action.previousFee).equal(4000n);
		expect(action.auxiliarySweep!.previousFee).equal(4000n);
	});
	it('rejects a funded shared candidate after one original output confirms elsewhere', () => {
		const f = setup(),
			monitor = new ChainMonitor(f.state, destination, 10, priv(2), priv(3));
		const action = monitor
			.handleFundingSpent(f.parent, 100)
			.find((a) => a.type === ChainActionType.FEE_BUMP_AND_BROADCAST);
		if (!action || action.type !== ChainActionType.FEE_BUMP_AND_BROADCAST)
			throw Error('missing action');
		const tx = funded(action.tx),
			signed = action.auxiliarySweep!.sign(
				tx.toBuffer(),
				[f.local.output, f.htlc.output, feeScript],
				[355n, 355n, 10000n]
			);
		const competing = resolveRevokedCommitmentOutputs(
			f.state,
			f.outputs,
			0n,
			f.parent,
			destination,
			10,
			priv(2),
			priv(3),
			bitcoin.networks.regtest,
			100,
			new Set([1])
		)[0].spendTx!;
		monitor.handleOutputSpent(f.parent.getId(), 0, competing, 101);
		const remainingBefore = monitor
			.getTrackedOutputs()
			.find((o) => o.outputIndex === 1)!.auxiliaryData;
		expect(
			action.auxiliarySweep!.finalize(
				signed.transaction,
				signed.auxiliaryData,
				3000n
			)
		).equal(false);
		const remaining = monitor
			.getTrackedOutputs()
			.find((o) => o.outputIndex === 1)!;
		expect(remaining.auxiliaryData).deep.equal(remainingBefore);
		expect(remaining.auxiliaryFeeFunded).not.equal(true);
		expect(remaining.sweepTxHex).not.equal(
			bitcoin.Transaction.fromBuffer(signed.transaction).toHex()
		);
	});
	it('keeps revoked second-level key tweaks when funding a 355 sat carrier', () => {
		const f = setup(),
			tree = buildTaprootSecondLevelOutput(
				f.revocation,
				f.delayed,
				12,
				undefined,
				leaf
			),
			parent = new bitcoin.Transaction();
		parent.version = 2;
		parent.addInput(f.parent.getHash(), 1);
		parent.addOutput(tree.output, 355);
		const [result] = resolveRevokedSecondLevelOutput(
			f.state,
			parent,
			100,
			0n,
			destination,
			10,
			priv(2)
		);
		expect(result.auxiliaryFunding).not.equal(undefined);
		const tx = funded(result.spendTx!.toBuffer()),
			scripts = [tree.output, feeScript],
			values = [355n, 10000n],
			signed = result.auxiliaryFunding!.sign(tx.toBuffer(), scripts, values),
			final = bitcoin.Transaction.fromBuffer(signed.transaction);
		expect(final.outs[0].value).equal(355);
		expect(
			ecc.verifySchnorr(
				final.hashForWitnessV1(0, scripts, values.map(Number), 0),
				tree.outputKey,
				final.ins[0].witness[0]
			)
		).equal(true);
		const plain = buildTaprootSecondLevelOutput(f.revocation, f.delayed, 12);
		expect(
			ecc.verifySchnorr(
				final.hashForWitnessV1(0, scripts, values.map(Number), 0),
				plain.outputKey,
				final.ins[0].witness[0]
			)
		).equal(false);
		expect(() =>
			result.auxiliaryFunding!.sign(
				tx.toBuffer(),
				[plain.output, feeScript],
				values
			)
		).throw('prevouts');
	});
	it('offers verified independent tower templates whose signatures survive appended fees', () => {
		const f = setup(),
			p = buildAuxiliaryJusticePackage({
				state: f.state,
				revokedTransaction: f.parent.toBuffer(),
				destinationScript: destination,
				feeRates: [10],
				revocationBasepointSecret: priv(2),
				paymentBasepointSecret: priv(3),
				network: bitcoin.networks.regtest
			});
		expect(p.sweeps).length(2);
		for (const sweep of p.sweeps) {
			expect(sweep.feeSponsorship?.type).equal('all-anyonecanpay');
			const base = bitcoin.Transaction.fromHex(sweep.transaction),
				tx = bitcoin.Transaction.fromBuffer(base.toBuffer()),
				previous = f.parent.outs[base.ins[0].index],
				sig = tx.ins[0].witness[0],
				leafScript = tx.ins[0].witness[1];
			tx.addInput(Buffer.alloc(32, 0x44), 0);
			expect(sig.length).equal(65);
			expect(sig[64]).equal(0x81);
			const digest = tx.hashForWitnessV1(
				0,
				[previous.script, feeScript],
				[previous.value, 10000],
				0x81,
				leafScript ? tapleafHash(leafScript) : undefined
			);
			expect(
				ecc.verifySchnorr(
					digest,
					leafScript ? f.revocation.subarray(1) : previous.script.subarray(2),
					sig.subarray(0, 64)
				)
			).equal(true);
			tx.addOutput(destination, 330);
			expect(
				ecc.verifySchnorr(
					tx.hashForWitnessV1(
						0,
						[previous.script, feeScript],
						[previous.value, 10000],
						0x81,
						leafScript ? tapleafHash(leafScript) : undefined
					),
					leafScript ? f.revocation.subarray(1) : previous.script.subarray(2),
					sig.subarray(0, 64)
				)
			).equal(false);
		}
		const changed = structuredClone(p),
			tx = bitcoin.Transaction.fromHex(changed.sweeps[0].transaction);
		tx.outs[0].value++;
		changed.sweeps[0].transaction = tx.toHex();
		expect(() => validateAuxiliaryJusticePackage(changed)).throw('signature');
		const wrong = structuredClone(p);
		wrong.sweeps[0].feeSponsorship!.prevoutValue = '356';
		expect(() => validateAuxiliaryJusticePackage(wrong)).throw('descriptor');
		const unsigned = structuredClone(p);
		delete unsigned.sweeps[0].feeSponsorship;
		expect(() => validateAuxiliaryJusticePackage(unsigned)).throw('value');
	});
	it('restricts pre-signed sponsorship to independent one-input remedies', () => {
		const f = setup(),
			[result] = resolveRevokedCommitmentOutputs(
				f.state,
				f.outputs,
				0n,
				f.parent,
				destination,
				10,
				priv(2),
				priv(3)
			);
		expect(() =>
			result.auxiliaryFunding!.sign(
				result.spendTx!.toBuffer(),
				[f.local.output, f.htlc.output],
				[355n, 355n],
				0x81
			)
		).throw('single input');
	});
});
