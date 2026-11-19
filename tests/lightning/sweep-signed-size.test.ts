/**
 * Every sweep of a plain (not asset) channel output pays at least the rate it
 * is built at, measured on the signed transaction.
 *
 * They were priced from a table by output type (113 vbytes for a to_local
 * sweep), and the signed transaction is larger: 121 vbytes to a P2WPKH
 * destination and 133 to a P2TR one. At 1 sat/vB the sweep paid about 0.93
 * sat/vB and a node with a 1 sat/vB relay floor refused it.
 *
 * Each sweep is built through its resolver, for a static_remotekey, an anchor
 * and a taproot channel, to both destination types and at two rates.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isAnchorChannel,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import {
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	derivePublicKey,
	deriveRevocationPubkey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import type { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	classifyOutputs,
	resolveOurCommitmentOutputs,
	resolveRevokedCommitmentOutputs,
	resolveRevokedSecondLevelOutput,
	resolveSecondLevelHtlcOutput,
	resolveTheirCurrentCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import type { IResolvedOutput } from '../../src/lightning/chain/output-resolver';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import { buildToLocalScript } from '../../src/lightning/script/commitment';
import { buildTaprootSecondLevelOutput } from '../../src/lightning/script/commitment-taproot';
import type { IChannelState } from '../../src/lightning/channel/channel-state';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { COMMIT_ALL } from './helpers/channel-persistence';

bitcoin.initEccLib(ecc);

const NETWORK = bitcoin.networks.regtest;

type Kind = 'static_remotekey' | 'anchors' | 'taproot';

const DESTINATIONS: Record<string, Buffer> = {
	P2WPKH: Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 7)]),
	P2TR: Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32, 7)])
};

const RATES = [1, 10];

function seedFor(id: string): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`sweep-signed-size-${id}`))
		.digest();
}

function privAt(seed: Buffer, i: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([i]))
		.digest();
}

function basepointsOf(seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(privAt(seed, 0)),
		revocationBasepoint: getPublicKey(privAt(seed, 1)),
		paymentBasepoint: getPublicKey(privAt(seed, 2)),
		delayedPaymentBasepoint: getPublicKey(privAt(seed, 3)),
		htlcBasepoint: getPublicKey(privAt(seed, 4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function configOf(seed: Buffer, kind: Kind | 'peer'): IChannelManagerConfig {
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: 2500 },
		localBasepoints: basepointsOf(seed),
		localPerCommitmentSeed: seedFor(`commit-${seed.toString('hex')}`),
		localFundingPrivkey: privAt(seed, 0),
		htlcBasepointSecret: privAt(seed, 4),
		preferAnchors: kind === 'anchors',
		preferTaproot: kind === 'taproot',
		persistence: COMMIT_ALL
	};
}

interface IFixture {
	state: IChannelState;
	aliceSeed: Buffer;
	preimages: Map<string, Buffer>;
	revokedTx: bitcoin.Transaction;
	revokedNumber: bigint;
}

/**
 * A channel of the given kind whose commitments carry an HTLC each way, and
 * a commitment of the peer's from before they were added, revoked since.
 */
function channelWithHtlcs(kind: Kind): IFixture {
	const aliceSeed = seedFor(`alice-${kind}`);
	const bobSeed = seedFor(`bob-${kind}`);
	const aliceCfg = configOf(aliceSeed, kind);
	const bobCfg = configOf(bobSeed, 'peer');
	const alice = new ChannelManager(aliceCfg);
	const bob = new ChannelManager(bobCfg);
	const aPub = aliceCfg.localBasepoints.fundingPubkey.toString('hex');
	const bPub = bobCfg.localBasepoints.fundingPubkey.toString('hex');
	alice.on('message:outbound', (peer: string, type: number, data: Buffer) => {
		if (peer === bPub) bob.handleMessage(aPub, type, data);
	});
	bob.on('message:outbound', (peer: string, type: number, data: Buffer) => {
		if (peer === aPub) alice.handleMessage(bPub, type, data);
	});

	const channel = alice.openChannel(bPub, 3_000_000n, 1_500_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	const opened = channel.getFullState();
	expect(opened.state).to.equal(ChannelState.NORMAL);
	expect(isTaprootChannel(opened.channelType)).to.equal(kind === 'taproot');
	expect(isAnchorChannel(opened.channelType)).to.equal(
		kind !== 'static_remotekey'
	);

	const revokedNumber = opened.remoteCommitmentNumber;
	const revokedTx = buildRemoteCommitment(
		opened,
		opened.remoteCurrentPerCommitmentPoint!
	).result.tx;

	const preimages = new Map<string, Buffer>();
	const add = (from: ChannelManager, msat: bigint, cltv: number): void => {
		const preimage = crypto.randomBytes(32);
		const hash = crypto.createHash('sha256').update(preimage).digest();
		preimages.set(hash.toString('hex'), preimage);
		expect(
			from.addHtlc(channelId, msat, hash, cltv, Buffer.alloc(1366)).ok
		).to.equal(true);
	};
	add(bob, 300_000_000n, 800);
	add(alice, 200_000_000n, 900);

	const state = channel.getFullState();
	expect(state.remoteCommitmentNumber > revokedNumber).to.equal(true);
	expect(
		state.shaChainStore.getSecret(MAX_INDEX - revokedNumber),
		'the earlier commitment of the peer is revoked'
	).to.not.equal(undefined);
	return { state, aliceSeed, preimages, revokedTx, revokedNumber };
}

/** Our commitment, with the outputs it carries. */
function ourCommitment(fx: IFixture): {
	tx: bitcoin.Transaction;
	number: bigint;
} {
	const point = perCommitmentPointFromSecret(
		generateFromSeed(
			fx.state.localPerCommitmentSeed,
			MAX_INDEX - fx.state.localCommitmentNumber
		)
	);
	return {
		tx: buildLocalCommitment(fx.state, point).result.tx,
		number: fx.state.localCommitmentNumber
	};
}

/**
 * A transaction of the peer's that spends an HTLC output of their revoked
 * commitment: its one output is the second-level output we claim with the
 * revocation key.
 */
function revokedSecondLevelTx(fx: IFixture): bitcoin.Transaction {
	const state = fx.state;
	const point = perCommitmentPointFromSecret(
		state.shaChainStore.getSecret(MAX_INDEX - fx.revokedNumber)!
	);
	const revocationPubkey = deriveRevocationPubkey(
		state.localBasepoints.revocationBasepoint,
		point
	);
	const delayedPubkey = derivePublicKey(
		state.remoteBasepoints!.delayedPaymentBasepoint,
		point
	);
	const toSelfDelay = state.localConfig.toSelfDelay;
	const script = isTaprootChannel(state.channelType)
		? buildTaprootSecondLevelOutput(
				revocationPubkey,
				delayedPubkey,
				toSelfDelay,
				NETWORK
		  ).output
		: bitcoin.payments.p2wsh({
				redeem: {
					output: buildToLocalScript(
						revocationPubkey,
						delayedPubkey,
						toSelfDelay
					)
				}
		  }).output!;
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(script, 180_000);
	return tx;
}

interface ISweep {
	label: string;
	tx: bitcoin.Transaction;
	fee: number;
	/** A sweep priced from its own size, which pays no more than one vbyte over. */
	exact: boolean;
}

const outpoint = (txid: string, index: number): string => `${txid}:${index}`;

/**
 * The signed sweeps among the resolved outputs, each with the fee it pays.
 * A witness the resolver returns beside the transaction is put in place.
 */
function signedSweeps(
	label: string,
	resolved: IResolvedOutput[],
	exact: boolean
): ISweep[] {
	const amounts = new Map<string, bigint>();
	for (const r of resolved) {
		amounts.set(
			outpoint(r.trackedOutput.txid, r.trackedOutput.outputIndex),
			r.trackedOutput.amount
		);
	}
	const txs = new Set<bitcoin.Transaction>();
	for (const r of resolved) {
		if (!r.spendTx) continue;
		txs.add(r.spendTx);
		if (!r.witness) continue;
		const index = r.spendTx.ins.findIndex(
			(input) =>
				outpoint(
					Buffer.from(input.hash).reverse().toString('hex'),
					input.index
				) === outpoint(r.trackedOutput.txid, r.trackedOutput.outputIndex)
		);
		if (index >= 0 && r.spendTx.ins[index].witness.length === 0) {
			r.spendTx.setWitness(index, r.witness);
		}
	}
	return [...txs].map((tx) => {
		let totalIn = 0n;
		for (const input of tx.ins) {
			expect(
				input.witness.length,
				`${label}: every input is signed`
			).to.be.above(0);
			const amount = amounts.get(
				outpoint(Buffer.from(input.hash).reverse().toString('hex'), input.index)
			);
			expect(
				amount,
				`${label}: the amount of every input is known`
			).to.not.equal(undefined);
			totalIn += amount!;
		}
		const totalOut = tx.outs.reduce((sum, out) => sum + BigInt(out.value), 0n);
		return { label, tx, fee: Number(totalIn - totalOut), exact };
	});
}

/** Every plain sweep the resolvers build for the fixture's channel. */
function everySweep(fx: IFixture, destination: Buffer, rate: number): ISweep[] {
	const state = fx.state;
	const sweeps: ISweep[] = [];

	// Our commitment: the to_local sweep, and the second-level transactions
	// whose outputs are swept next.
	const ours = ourCommitment(fx);
	const ourResolved = resolveOurCommitmentOutputs(
		state,
		classifyOutputs(ours.tx, state, CommitmentType.OUR_COMMITMENT, ours.number),
		ours.number,
		destination,
		rate,
		fx.preimages,
		privAt(fx.aliceSeed, 3)
	);
	const toLocal = ourResolved.filter(
		(r) => r.trackedOutput.outputType === OutputType.TO_LOCAL
	);
	expect(toLocal.length, 'a to_local sweep').to.equal(1);
	sweeps.push(...signedSweeps('to_local', toLocal, true));

	const secondLevel = ourResolved.filter(
		(r) => r.trackedOutput.outputType !== OutputType.TO_LOCAL && r.spendTx
	);
	expect(secondLevel.length, 'both HTLCs go to the second level').to.equal(2);
	for (const htlc of secondLevel) {
		const r = resolveSecondLevelHtlcOutput(
			state,
			htlc.spendTx!,
			200,
			ours.number,
			destination,
			rate,
			privAt(fx.aliceSeed, 3),
			NETWORK
		);
		expect(r, 'the second-level output is ours').to.not.equal(null);
		sweeps.push(
			...signedSweeps(
				`second level of ${htlc.trackedOutput.outputType}`,
				[r!],
				true
			)
		);
	}

	// Their current commitment: our to_remote and both HTLC claims.
	const theirs = buildRemoteCommitment(
		state,
		state.remoteCurrentPerCommitmentPoint!
	).result.tx;
	const theirResolved = resolveTheirCurrentCommitmentOutputs(
		state,
		classifyOutputs(
			theirs,
			state,
			CommitmentType.THEIR_CURRENT_COMMITMENT,
			state.remoteCommitmentNumber
		),
		destination,
		rate,
		fx.preimages,
		privAt(fx.aliceSeed, 2),
		privAt(fx.aliceSeed, 4),
		state.remoteCurrentPerCommitmentPoint!
	);
	for (const type of [
		OutputType.TO_REMOTE,
		OutputType.OFFERED_HTLC,
		OutputType.RECEIVED_HTLC
	]) {
		const claim = theirResolved.filter(
			(r) => r.trackedOutput.outputType === type && r.spendTx
		);
		expect(claim.length, `a claim of ${type} on their commitment`).to.equal(1);
		sweeps.push(...signedSweeps(`their ${type}`, claim, true));
	}

	// Their revoked commitment: our to_remote and the penalty.
	const revokedResolved = resolveRevokedCommitmentOutputs(
		state,
		classifyOutputs(
			fx.revokedTx,
			state,
			CommitmentType.THEIR_REVOKED_COMMITMENT,
			fx.revokedNumber
		),
		fx.revokedNumber,
		fx.revokedTx,
		destination,
		rate,
		privAt(fx.aliceSeed, 1),
		privAt(fx.aliceSeed, 2),
		NETWORK
	);
	const revokedToRemote = revokedResolved.filter(
		(r) => r.trackedOutput.outputType === OutputType.TO_REMOTE
	);
	expect(revokedToRemote.length, 'a claim of the revoked to_remote').to.equal(
		1
	);
	sweeps.push(...signedSweeps('revoked to_remote', revokedToRemote, true));
	const penalty = revokedResolved.filter(
		(r) => r.trackedOutput.outputType === OutputType.TO_LOCAL
	);
	expect(penalty.length, 'a penalty on the revoked to_local').to.equal(1);
	// The penalty is priced by a bound over every input it may batch.
	sweeps.push(...signedSweeps('penalty', penalty, false));

	// A second-level transaction of theirs off the revoked commitment.
	const revokedSecond = resolveRevokedSecondLevelOutput(
		state,
		revokedSecondLevelTx(fx),
		300,
		fx.revokedNumber,
		destination,
		rate,
		privAt(fx.aliceSeed, 1),
		NETWORK
	);
	expect(revokedSecond.length, 'a claim of the revoked second level').to.equal(
		1
	);
	sweeps.push(...signedSweeps('revoked second level', revokedSecond, true));

	return sweeps;
}

describe('Plain sweeps pay their rate on the signed size (#2106)', function () {
	this.timeout(60_000);

	for (const kind of ['static_remotekey', 'anchors', 'taproot'] as Kind[]) {
		describe(kind, function () {
			let fx: IFixture;
			before(function () {
				fx = channelWithHtlcs(kind);
			});

			for (const [name, destination] of Object.entries(DESTINATIONS)) {
				for (const rate of RATES) {
					it(`to ${name} at ${rate} sat/vB`, function () {
						const sweeps = everySweep(fx, destination, rate);
						for (const sweep of sweeps) {
							const vsize = sweep.tx.virtualSize();
							expect(
								sweep.fee,
								`${sweep.label}: ${sweep.fee} sat for ${vsize} vbytes`
							).to.be.at.least(Math.ceil(rate * vsize));
							if (sweep.exact) {
								// Priced from its own size: a signature one byte
								// shorter than the longest is all it may differ by.
								expect(
									sweep.fee,
									`${sweep.label}: ${sweep.fee} sat for ${vsize} vbytes`
								).to.be.at.most(Math.ceil(rate * (vsize + 1)));
							}
							for (const out of sweep.tx.outs) {
								expect(out.script.equals(destination)).to.equal(true);
							}
						}
					});
				}
			}
		});
	}
});
