/**
 * Force-close resolution during the two-phase HTLC removal window
 * (issues #561 and #556).
 *
 * An HTLC that was just fulfilled or failed off-chain keeps its output in
 * the broadcast commitment until the removal is irrevocably committed
 * (removalRemoteCommitted on either side's commitment, since the peer's
 * previous commitment stays broadcastable through the second phase), and
 * the stored remote HTLC signatures cover it. The output
 * matcher used to skip every non PENDING/COMMITTED entry, so:
 *  - a preimage-held received HTLC was never claimed via HTLC-success
 *    and fell to the peer's timeout (#561), on the exact path
 *    HTLC_CLAIM_FORCE_CLOSE force-closes to protect, and
 *  - the skipped output shifted htlcSigIndex so every later HTLC claim
 *    paired with the wrong remote signature (#556).
 * These tests pin the fix: window entries match per the commitment
 * builder's own inclusion predicate, indices align with the commitment's
 * HTLC output order, and fully removed entries still never match.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	deriveCommitmentKeys,
	buildLocalCommitment,
	signRemoteCommitment
} from '../../src/lightning/channel/commitment-builder';
import {
	createOpenerState,
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IHtlcEntry
} from '../../src/lightning/channel/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { getPublicKey, verify } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { deriveChannelId } from '../../src/lightning/channel/validation';
import {
	classifyOutputs,
	resolveOurCommitmentOutputs,
	resolveTheirCurrentCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import { CommitmentType, OutputType } from '../../src/lightning/chain/types';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

bitcoin.initEccLib(ecc);

const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;
const SIGHASH_ANCHOR =
	bitcoin.Transaction.SIGHASH_SINGLE | bitcoin.Transaction.SIGHASH_ANYONECANPAY;

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`removal-window-${id}`))
		.digest();
}
function priv(seed: Buffer, i: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([i]))
		.digest();
}
function basepoints(seed: Buffer): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(priv(seed, 0)),
		revocationBasepoint: getPublicKey(priv(seed, 1)),
		paymentBasepoint: getPublicKey(priv(seed, 2)),
		delayedPaymentBasepoint: getPublicKey(priv(seed, 3)),
		htlcBasepoint: getPublicKey(priv(seed, 4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}
function point(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}
function anchorChannelType(): Buffer {
	const f = FeatureFlags.empty();
	f.setCompulsory(Feature.STATIC_REMOTE_KEY);
	f.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	return f.toBuffer();
}
function taprootChannelType(): Buffer {
	const f = FeatureFlags.empty();
	f.setCompulsory(Feature.STATIC_REMOTE_KEY);
	f.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	f.setCompulsory(Feature.OPTION_TAPROOT);
	return f.toBuffer();
}
type ChannelKind = 'legacy' | 'anchor' | 'taproot';
function channelTypeFor(kind: ChannelKind): Buffer | null {
	if (kind === 'anchor') return anchorChannelType();
	if (kind === 'taproot') return taprootChannelType();
	return null;
}

interface IHtlcSpec {
	key: string;
	amountMsat: bigint;
	/** From the OPENER's perspective. */
	direction: HtlcDirection;
	state: HtlcState;
	/** Opener entry is in the removal window (mirror flags set on both sides). */
	removalWindow?: boolean;
	preimage: Buffer;
}

function makeHtlcSpec(
	key: string,
	amountMsat: bigint,
	direction: HtlcDirection,
	state: HtlcState,
	removalWindow?: boolean
): IHtlcSpec {
	return {
		key,
		amountMsat,
		direction,
		state,
		removalWindow,
		preimage: crypto.createHash('sha256').update(Buffer.from(key)).digest()
	};
}

/**
 * Hand-build a NORMAL opener/acceptor pair carrying the given HTLC set,
 * with the acceptor's REAL second-level signatures over the opener's
 * commitment stored as opener.remoteHtlcSignatures (mirroring the live
 * commitment_signed flow, which stores them before the removal round
 * completes).
 */
function makeChannelPair(
	specs: IHtlcSpec[],
	kind: ChannelKind
): {
	openerState: IChannelState;
	acceptorState: IChannelState;
	openerLocalPoint: Buffer;
	acceptorLocalPoint: Buffer;
	openerSeed: Buffer;
	htlcSignatures: Buffer[];
} {
	const openerSeed = makeSeed(1),
		acceptorSeed = makeSeed(2);
	const openerCommitSeed = makeSeed(3),
		acceptorCommitSeed = makeSeed(4);
	const ob = basepoints(openerSeed),
		ab = basepoints(acceptorSeed);
	ob.firstPerCommitmentPoint = point(openerCommitSeed, 0n);
	ab.firstPerCommitmentPoint = point(acceptorCommitSeed, 0n);

	const fundingTxid = crypto
		.createHash('sha256')
		.update(Buffer.from('fund'))
		.digest();
	const channelId = deriveChannelId(fundingTxid, 0);
	const channelType = channelTypeFor(kind);

	const openerState = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: ob,
		localPerCommitmentSeed: openerCommitSeed
	});
	openerState.remoteBasepoints = ab;
	openerState.remoteConfig = { ...DEFAULT_CHANNEL_CONFIG };
	openerState.fundingTxid = fundingTxid;
	openerState.fundingOutputIndex = 0;
	openerState.channelId = channelId;
	openerState.state = ChannelState.NORMAL;
	openerState.remoteCurrentPerCommitmentPoint = ab.firstPerCommitmentPoint;
	openerState.channelType = channelType;
	openerState.localBalanceMsat = 600_000_000n;
	openerState.remoteBalanceMsat = 400_000_000n;

	const acceptorState = createAcceptorState({
		temporaryChannelId: openerState.temporaryChannelId,
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: ab,
		localPerCommitmentSeed: acceptorCommitSeed,
		remoteBasepoints: ob,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	acceptorState.fundingTxid = fundingTxid;
	acceptorState.fundingOutputIndex = 0;
	acceptorState.channelId = channelId;
	acceptorState.state = ChannelState.NORMAL;
	acceptorState.remoteCurrentPerCommitmentPoint = ob.firstPerCommitmentPoint;
	acceptorState.channelType = channelType;
	acceptorState.localBalanceMsat = 400_000_000n;
	acceptorState.remoteBalanceMsat = 600_000_000n;

	for (let i = 0; i < specs.length; i++) {
		const s = specs[i];
		const paymentHash = crypto.createHash('sha256').update(s.preimage).digest();
		const base = {
			id: BigInt(i),
			amountMsat: s.amountMsat,
			paymentHash,
			cltvExpiry: 500_000 + i,
			onionRoutingPacket: Buffer.alloc(1366)
		};
		const opener: IHtlcEntry = {
			...base,
			direction: s.direction,
			state: s.state
		};
		const mirror: IHtlcEntry = {
			...base,
			direction:
				s.direction === HtlcDirection.RECEIVED
					? HtlcDirection.OFFERED
					: HtlcDirection.RECEIVED,
			state: s.state
		};
		if (s.removalWindow) {
			// The live flow: our fulfill/fail sets removalRemoteCommitted false
			// on our RECEIVED entry; the peer's handler sets both flags false on
			// its OFFERED mirror (and vice versa for our OFFERED entries).
			if (s.direction === HtlcDirection.RECEIVED) {
				opener.removalRemoteCommitted = false;
				mirror.removalRemoteCommitted = false;
				mirror.removalLocallyRevoked = false;
			} else {
				opener.removalRemoteCommitted = false;
				opener.removalLocallyRevoked = false;
				mirror.removalRemoteCommitted = false;
			}
		}
		openerState.htlcs.set(s.key, opener);
		acceptorState.htlcs.set(s.key, mirror);
	}

	const openerLocalPoint = point(openerCommitSeed, 0n);
	let htlcSignatures: Buffer[] = [];
	if (kind !== 'taproot') {
		const acceptorSigner = new ChannelSigner(
			priv(acceptorSeed, 0),
			priv(acceptorSeed, 4)
		);
		({ htlcSignatures } = signRemoteCommitment(
			acceptorState,
			acceptorSigner,
			openerLocalPoint
		));
		openerState.remoteHtlcSignatures = htlcSignatures;
	}

	return {
		openerState,
		acceptorState,
		openerLocalPoint,
		acceptorLocalPoint: point(acceptorCommitSeed, 0n),
		openerSeed,
		htlcSignatures
	};
}

describe('HTLC removal-window force-close resolution (issues #561/#556)', function () {
	for (const kind of ['legacy', 'anchor'] as const) {
		const anchor = kind === 'anchor';
		const label = kind;

		it(`claims a just-fulfilled inbound HTLC via HTLC-success (${label})`, function () {
			const spec = makeHtlcSpec(
				'h0',
				50_000_000n,
				HtlcDirection.RECEIVED,
				HtlcState.FULFILLED,
				true
			);
			const { openerState, openerLocalPoint, openerSeed, htlcSignatures } =
				makeChannelPair([spec], kind);

			// The broadcast commitment (prepareForceClose uses the same builder)
			// still carries the HTLC output.
			const built = buildLocalCommitment(openerState, openerLocalPoint);
			const tracked = classifyOutputs(
				built.result.tx,
				openerState,
				CommitmentType.OUR_COMMITMENT,
				0n
			);
			const htlcOut = tracked.find(
				(o) => o.outputType === OutputType.RECEIVED_HTLC
			);
			expect(htlcOut, 'removal-window HTLC output is tracked').to.exist;
			expect(htlcOut!.htlcSigIndex).to.equal(0);

			// The preimage is always recorded before the fulfill, so the
			// resolver holds everything needed for the HTLC-success.
			const paymentHash = crypto
				.createHash('sha256')
				.update(spec.preimage)
				.digest();
			const resolved = resolveOurCommitmentOutputs(
				openerState,
				tracked,
				0n,
				Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]),
				10,
				new Map([[paymentHash.toString('hex'), spec.preimage]]),
				priv(openerSeed, 3),
				priv(openerSeed, 4),
				htlcSignatures
			);
			const claim = resolved.find(
				(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
			);
			expect(claim?.spendTx, 'HTLC-success built').to.exist;
			expect(claim?.witness, 'HTLC-success witnessed').to.exist;

			// Decisive: the peer's stored signature verifies against the exact
			// second-level tx the resolver built.
			const keys = deriveCommitmentKeys(
				openerState.localBasepoints,
				openerState.remoteBasepoints!,
				openerLocalPoint,
				true
			);
			const sighashType = anchor ? SIGHASH_ANCHOR : SIGHASH_ALL;
			const sigHash = claim!.spendTx!.hashForWitnessV0(
				0,
				claim!.trackedOutput.witnessScript!,
				Number(claim!.trackedOutput.amount),
				sighashType
			);
			expect(
				verify(sigHash, keys.remoteHtlcPubkey, htlcSignatures[0]),
				'peer HTLC signature verifies against the resolver tx'
			).to.equal(true);
		});

		it(`aligns htlcSigIndex across a removal-window output (${label})`, function () {
			// Three live outputs; the window entry must be counted, or the two
			// later claims pair with the wrong remote signatures (#556).
			// The window HTLC is the SMALLEST amount so BIP69 orders its output
			// FIRST: skipping it would shift every later htlcSigIndex, which is
			// exactly the #556 failure this test pins.
			const specs = [
				makeHtlcSpec(
					'h0',
					20_000_000n,
					HtlcDirection.RECEIVED,
					HtlcState.FULFILLED,
					true
				),
				makeHtlcSpec(
					'h1',
					40_000_000n,
					HtlcDirection.RECEIVED,
					HtlcState.COMMITTED
				),
				makeHtlcSpec(
					'h2',
					30_000_000n,
					HtlcDirection.OFFERED,
					HtlcState.COMMITTED
				)
			];
			const { openerState, openerLocalPoint, openerSeed, htlcSignatures } =
				makeChannelPair(specs, kind);

			const built = buildLocalCommitment(openerState, openerLocalPoint);
			expect(built.result.outputMap.htlcs.length).to.equal(3);
			expect(htlcSignatures.length).to.equal(3);

			const tracked = classifyOutputs(
				built.result.tx,
				openerState,
				CommitmentType.OUR_COMMITMENT,
				0n
			);
			const htlcOutputs = tracked.filter(
				(o) =>
					o.outputType === OutputType.RECEIVED_HTLC ||
					o.outputType === OutputType.OFFERED_HTLC
			);
			expect(htlcOutputs.length, 'every present HTLC output tracked').to.equal(
				3
			);
			// Guard the fixture's premise: the window HTLC's output must come
			// FIRST among the HTLC outputs, or a skip could not shift anything.
			const windowHash = crypto
				.createHash('sha256')
				.update(specs[0].preimage)
				.digest();
			const firstHtlc = htlcOutputs.reduce((a, b) =>
				a.outputIndex < b.outputIndex ? a : b
			);
			expect(
				firstHtlc.paymentHash!.equals(windowHash),
				'the window output sorts first'
			).to.equal(true);
			// The invariant that broke: the k-th HTLC output of the commitment
			// (ascending output order) pairs with remoteHtlcSignatures[k].
			for (const o of htlcOutputs) {
				expect(o.htlcSigIndex).to.not.equal(undefined);
				expect(built.result.outputMap.htlcs[o.htlcSigIndex!]).to.equal(
					o.outputIndex
				);
			}

			// And the signatures actually verify against the second-level txs
			// the resolver builds for the two non-window claims.
			const preimages = new Map<string, Buffer>();
			for (const s of specs) {
				const hash = crypto.createHash('sha256').update(s.preimage).digest();
				preimages.set(hash.toString('hex'), s.preimage);
			}
			const resolved = resolveOurCommitmentOutputs(
				openerState,
				tracked,
				0n,
				Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]),
				10,
				preimages,
				priv(openerSeed, 3),
				priv(openerSeed, 4),
				htlcSignatures
			);
			const keys = deriveCommitmentKeys(
				openerState.localBasepoints,
				openerState.remoteBasepoints!,
				openerLocalPoint,
				true
			);
			const sighashType = anchor ? SIGHASH_ANCHOR : SIGHASH_ALL;
			let verified = 0;
			for (const r of resolved) {
				if (
					(r.trackedOutput.outputType !== OutputType.RECEIVED_HTLC &&
						r.trackedOutput.outputType !== OutputType.OFFERED_HTLC) ||
					!r.spendTx ||
					r.trackedOutput.htlcSigIndex === undefined
				) {
					continue;
				}
				const sigHash = r.spendTx.hashForWitnessV0(
					0,
					r.trackedOutput.witnessScript!,
					Number(r.trackedOutput.amount),
					sighashType
				);
				expect(
					verify(
						sigHash,
						keys.remoteHtlcPubkey,
						htlcSignatures[r.trackedOutput.htlcSigIndex]
					),
					`signature at index ${r.trackedOutput.htlcSigIndex} verifies`
				).to.equal(true);
				verified++;
			}
			expect(verified, 'all three claims carry verifying signatures').to.equal(
				3
			);
		});
	}

	it('a fully removed entry never matches an output still present in an old tx', function () {
		// Build the commitment WHILE the HTLC is live, so the transaction being
		// classified genuinely CONTAINS the output; then promote the entry to
		// fully-removed. The matcher must reject the candidate even though the
		// byte match would succeed: past the window that transaction is a
		// superseded (revoked-line) commitment, not a claimable current one,
		// and admitting settled entries unconditionally would track it.
		const spec = makeHtlcSpec(
			'h0',
			50_000_000n,
			HtlcDirection.RECEIVED,
			HtlcState.COMMITTED
		);
		const { openerState, openerLocalPoint } = makeChannelPair([spec], 'legacy');
		const withHtlc = buildLocalCommitment(openerState, openerLocalPoint);
		expect(withHtlc.result.outputMap.htlcs.length).to.equal(1);

		const entry = openerState.htlcs.get('h0')!;
		entry.state = HtlcState.FULFILLED;
		entry.removalRemoteCommitted = true;

		const tracked = classifyOutputs(
			withHtlc.result.tx,
			openerState,
			CommitmentType.OUR_COMMITMENT,
			0n
		);
		expect(
			tracked.some(
				(o) =>
					o.outputType === OutputType.RECEIVED_HTLC ||
					o.outputType === OutputType.OFFERED_HTLC
			),
			'output present in the tx, entry past the window: not tracked'
		).to.equal(false);
	});

	it('their commitment: an offered HTLC the peer failed is tracked in the window', function () {
		// The peer failed OUR offered HTLC; until we revoke for the removal,
		// their commitment still carries the output and our timeout claim is
		// the refund path. Previously the entry was skipped and the output
		// went entirely unwatched.
		const spec = makeHtlcSpec(
			'h0',
			50_000_000n,
			HtlcDirection.OFFERED,
			HtlcState.FAILED,
			true
		);
		const { openerState, acceptorState, acceptorLocalPoint } = makeChannelPair(
			[spec],
			'legacy'
		);

		// Their commitment is the acceptor's local one; its builder includes
		// the failed HTLC while the acceptor's own removal is uncommitted.
		const theirs = buildLocalCommitment(acceptorState, acceptorLocalPoint);
		expect(theirs.result.outputMap.htlcs.length).to.equal(1);

		const tracked = classifyOutputs(
			theirs.result.tx,
			openerState,
			CommitmentType.THEIR_CURRENT_COMMITMENT,
			0n
		);
		const htlcOut = tracked.find(
			(o) => o.outputType === OutputType.OFFERED_HTLC
		);
		expect(htlcOut, 'window OFFERED HTLC tracked on their commitment').to.exist;
	});

	for (const kind of ['legacy', 'anchor', 'taproot'] as const) {
		it(`their commitment: an offered HTLC the peer failed stays tracked through the SECOND removal phase (${kind})`, function () {
			// Our revoke_and_ack for the peer's removal round flips
			// removalLocallyRevoked one round BEFORE the peer revokes the
			// commitment that carries the output. Matching on that first-phase
			// flag alone dropped the entry there, so a peer confirming its still
			// valid previous commitment left the offered output unwatched and the
			// timeout sweep unarmed (issue #641).
			const spec = makeHtlcSpec(
				'h0',
				50_000_000n,
				HtlcDirection.OFFERED,
				HtlcState.COMMITTED
			);
			const { openerState, acceptorState, acceptorLocalPoint } =
				makeChannelPair([spec], kind);

			// The transaction under classification: the peer's commitment as
			// signed BEFORE the removal, which it can still broadcast.
			const theirs = buildLocalCommitment(acceptorState, acceptorLocalPoint);
			expect(theirs.result.outputMap.htlcs.length).to.equal(1);

			const offeredCount = (): number =>
				classifyOutputs(
					theirs.result.tx,
					openerState,
					CommitmentType.THEIR_CURRENT_COMMITMENT,
					0n
				).filter((o) => o.outputType === OutputType.OFFERED_HTLC).length;

			// handleUpdateFailHtlc's exact mutation: first phase, both to go.
			const entry = openerState.htlcs.get('h0')!;
			entry.state = HtlcState.FAILED;
			entry.removalLocallyRevoked = false;
			entry.removalRemoteCommitted = false;
			expect(offeredCount(), 'first phase: output tracked').to.equal(1);

			// handleCommitmentSigned's: we revoked, the peer has not.
			entry.removalLocallyRevoked = true;
			expect(
				offeredCount(),
				'second phase: the SAME tx keeps its offered HTLC tracked'
			).to.equal(1);

			// The peer's revoke_and_ack for our covering commitment_signed ends
			// the window; past it the transaction is a revoked-line commitment.
			entry.removalRemoteCommitted = true;
			expect(offeredCount(), 'fully removed: not tracked').to.equal(0);
		});
	}

	for (const kind of ['legacy', 'anchor'] as const) {
		it(`their commitment: a just-fulfilled inbound HTLC stays claimable by preimage (${kind})`, function () {
			// The peer's CURRENT signed commitment predates our update_fulfill,
			// so its HTLC output survives our settle until the peer revokes for
			// the removal. The matcher used to drop the RECEIVED/FULFILLED
			// entry here, so a peer force-closing right after our fulfill left
			// the preimage-paid output to its own timeout sweep.
			const spec = makeHtlcSpec(
				'h0',
				50_000_000n,
				HtlcDirection.RECEIVED,
				HtlcState.COMMITTED
			);
			const { openerState, acceptorState, acceptorLocalPoint, openerSeed } =
				makeChannelPair([spec], kind);

			// The on-chain tx: the peer's commitment as signed BEFORE the
			// fulfill (its builder still includes the live HTLC).
			const theirs = buildLocalCommitment(acceptorState, acceptorLocalPoint);
			expect(theirs.result.outputMap.htlcs.length).to.equal(1);

			const before = classifyOutputs(
				theirs.result.tx,
				openerState,
				CommitmentType.THEIR_CURRENT_COMMITMENT,
				0n
			).filter((o) => o.outputType === OutputType.RECEIVED_HTLC);
			expect(before.length, 'baseline: live HTLC tracked').to.equal(1);

			// Exactly fulfillHtlc's mutation: preimage revealed, removal begun.
			const entry = openerState.htlcs.get('h0')!;
			entry.state = HtlcState.FULFILLED;
			entry.removalRemoteCommitted = false;

			const after = classifyOutputs(
				theirs.result.tx,
				openerState,
				CommitmentType.THEIR_CURRENT_COMMITMENT,
				0n
			).filter((o) => o.outputType === OutputType.RECEIVED_HTLC);
			expect(
				after.length,
				'the SAME tx keeps its HTLC tracked through the window'
			).to.equal(1);

			// And the tracked output resolves to a real preimage spend.
			const paymentHash = crypto
				.createHash('sha256')
				.update(spec.preimage)
				.digest();
			const resolved = resolveTheirCurrentCommitmentOutputs(
				openerState,
				after,
				Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]),
				10,
				new Map([[paymentHash.toString('hex'), spec.preimage]]),
				priv(openerSeed, 2),
				priv(openerSeed, 4),
				acceptorLocalPoint
			);
			const claim = resolved.find(
				(r) => r.trackedOutput.outputType === OutputType.RECEIVED_HTLC
			);
			expect(claim?.spendTx, 'preimage claim built').to.exist;
			expect(claim?.witness, 'preimage claim witnessed').to.exist;
		});
	}

	it('taproot: removal-window outputs are tracked with aligned indices (our commitment)', function () {
		const specs = [
			makeHtlcSpec(
				'h0',
				20_000_000n,
				HtlcDirection.RECEIVED,
				HtlcState.FULFILLED,
				true
			),
			makeHtlcSpec(
				'h1',
				40_000_000n,
				HtlcDirection.RECEIVED,
				HtlcState.COMMITTED
			)
		];
		const { openerState, openerLocalPoint } = makeChannelPair(specs, 'taproot');
		const built = buildLocalCommitment(openerState, openerLocalPoint);
		expect(built.result.outputMap.htlcs.length).to.equal(2);

		const tracked = classifyOutputs(
			built.result.tx,
			openerState,
			CommitmentType.OUR_COMMITMENT,
			0n
		);
		const htlcOutputs = tracked.filter(
			(o) => o.outputType === OutputType.RECEIVED_HTLC
		);
		expect(htlcOutputs.length, 'both taproot HTLC outputs tracked').to.equal(2);
		for (const o of htlcOutputs) {
			expect(o.htlcSigIndex).to.not.equal(undefined);
			expect(built.result.outputMap.htlcs[o.htlcSigIndex!]).to.equal(
				o.outputIndex
			);
		}
	});

	it('taproot: a just-fulfilled inbound HTLC stays tracked on their commitment', function () {
		const spec = makeHtlcSpec(
			'h0',
			50_000_000n,
			HtlcDirection.RECEIVED,
			HtlcState.COMMITTED
		);
		const { openerState, acceptorState, acceptorLocalPoint } = makeChannelPair(
			[spec],
			'taproot'
		);
		const theirs = buildLocalCommitment(acceptorState, acceptorLocalPoint);
		expect(theirs.result.outputMap.htlcs.length).to.equal(1);

		const entry = openerState.htlcs.get('h0')!;
		entry.state = HtlcState.FULFILLED;
		entry.removalRemoteCommitted = false;

		const tracked = classifyOutputs(
			theirs.result.tx,
			openerState,
			CommitmentType.THEIR_CURRENT_COMMITMENT,
			0n
		);
		expect(
			tracked.some((o) => o.outputType === OutputType.RECEIVED_HTLC),
			'window RECEIVED HTLC tracked on their taproot commitment'
		).to.equal(true);
	});
});
