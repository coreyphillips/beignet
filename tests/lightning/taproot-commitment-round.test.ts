import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import {
	buildLocalCommitment,
	aggregateLocalCommitmentSig
} from '../../src/lightning/channel/commitment-builder';
import { taprootCommitmentSighash } from '../../src/lightning/channel/commitment-musig';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-round-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
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
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeConfig(
	seedId: number,
	preferTaproot: boolean
): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey,
		htlcBasepointSecret,
		preferTaproot
	};
}

function connectManagers(
	a: ChannelManager,
	aPub: string,
	b: ChannelManager,
	bPub: string
): void {
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bPub) b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aPub) a.handleMessage(bPub, type, payload);
	});
}

function perCommitmentPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(generateFromSeed(seed, MAX_INDEX - n));
}

/**
 * Aggregate the channel's stored partial (peer's partial over OUR local
 * commitment `commitmentNumber`) with our own, and assert a valid BIP340
 * key-spend signature for the 2-of-2 funding output — proving the round produced
 * a broadcastable signature for the new commitment.
 */
function assertCommitmentAggregates(
	channel: Channel,
	commitmentNumber: bigint
): void {
	const state = channel.getFullState();
	const signer = channel.getSigner();
	expect(signer, 'signer').to.not.be.null;
	expect(state.localNonce, 'current verification nonce').to.exist;
	expect(state.remoteSigningNonce, 'peer signing nonce').to.exist;
	expect(state.remoteCommitmentSignature, 'peer partial').to.exist;
	expect(state.remoteCommitmentSignature!.length).to.equal(32);

	const point = perCommitmentPoint(
		state.localPerCommitmentSeed,
		commitmentNumber
	);
	const finalSig = aggregateLocalCommitmentSig(
		state,
		signer!,
		state.localNonce!,
		state.remoteSigningNonce!,
		state.remoteCommitmentSignature!,
		point,
		commitmentNumber
	);
	const funding = createTaprootFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey
	);
	const built = buildLocalCommitment(state, point, commitmentNumber);
	const sighash = taprootCommitmentSighash(
		built.result.tx,
		funding.p2trOutput,
		Number(state.fundingSatoshis)
	);
	expect(ecc.verifySchnorr(sighash, funding.outputKey, finalSig)).to.equal(
		true
	);
}

describe('option_taproot commitment round + nonce rotation (Stage B)', function () {
	function setupReadyTaprootChannel(): {
		alice: ChannelManager;
		bob: ChannelManager;
		aliceChannel: Channel;
		bobChannel: Channel;
		channelId: Buffer;
	} {
		const alice = new ChannelManager(makeConfig(1, true));
		const bob = new ChannelManager(makeConfig(2, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
		connectManagers(alice, aPub, bob, bPub);

		const aliceChannel = alice.openChannel(bPub, 1_000_000n);
		const channelId = alice.createFunding(
			aliceChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		// Confirm funding on both → channel_ready exchange (seeds the #1 nonces).
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);

		const bobChannel = bob.getChannel(channelId)!;
		return { alice, bob, aliceChannel, bobChannel, channelId };
	}

	it('brings a taproot channel to NORMAL with the verification-nonce pipeline seeded', function () {
		const { aliceChannel, bobChannel } = setupReadyTaprootChannel();

		for (const ch of [aliceChannel, bobChannel]) {
			const s = ch.getFullState();
			expect(isTaprootChannel(s.channelType)).to.equal(true);
			expect(s.state).to.equal(ChannelState.NORMAL);
			// localNonce = our #0 funding nonce; localNextNonce = our #1 nonce
			// (advertised in channel_ready); remoteNonce = peer's #1 nonce.
			expect(s.localNonce, 'funding nonce #0').to.exist;
			expect(s.localNextNonce, 'next verification nonce #1').to.exist;
			expect(s.remoteNonce, "peer's #1 verification nonce").to.exist;
			expect(s.remoteNonce!.length).to.equal(66);
		}
	});

	it('completes a full no-HTLC commitment round, rotates nonces, and both #1 partials aggregate', function () {
		const { alice, aliceChannel, bobChannel, channelId } =
			setupReadyTaprootChannel();

		// Snapshot the verification nonces BEFORE the round.
		const aliceNonce0 = aliceChannel.getFullState().localNonce;
		const aliceNext1Before = aliceChannel.getFullState().localNextNonce;
		const bobNonce0 = bobChannel.getFullState().localNonce;

		// Opener raises the fee → drives a full commitment round (commitment_signed
		// + revoke_and_ack both ways) over the loopback.
		const res = alice.updateChannelFee(channelId, 1000);
		expect(res.ok, res.error).to.equal(true);

		// Both sides advanced to commitment #1.
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);
		expect(aliceChannel.getFullState().remoteCommitmentNumber).to.equal(1n);
		expect(bobChannel.getFullState().localCommitmentNumber).to.equal(1n);
		expect(bobChannel.getFullState().remoteCommitmentNumber).to.equal(1n);

		// Nonce rotation: the #1 nonce we advertised is now the CURRENT nonce
		// (localNonce), and a fresh #2 nonce has been generated. No secret reused:
		// the #0 funding nonce is gone, and localNext advanced.
		const aliceAfter = aliceChannel.getFullState();
		expect(Buffer.from(aliceAfter.localNonce!)).to.deep.equal(
			Buffer.from(aliceNext1Before!),
			'current nonce should be the previously-advertised #1 nonce'
		);
		expect(Buffer.from(aliceAfter.localNonce!)).to.not.deep.equal(
			Buffer.from(aliceNonce0!),
			'current nonce must differ from the spent #0 funding nonce'
		);
		expect(Buffer.from(aliceAfter.localNextNonce!)).to.not.deep.equal(
			Buffer.from(aliceNext1Before!),
			'a fresh next (#2) nonce must be generated'
		);
		expect(
			Buffer.from(bobChannel.getFullState().localNonce!)
		).to.not.deep.equal(
			Buffer.from(bobNonce0!),
			"bob's current nonce must differ from its spent #0 nonce"
		);

		// GATE: each side can aggregate its stored partials into a valid key-spend
		// signature over its own commitment #1.
		assertCommitmentAggregates(aliceChannel, 1n);
		assertCommitmentAggregates(bobChannel, 1n);
	});

	it('completes two sequential rounds reaching commitment #2 with valid aggregable partials', function () {
		const { alice, aliceChannel, bobChannel, channelId } =
			setupReadyTaprootChannel();

		expect(alice.updateChannelFee(channelId, 1000).ok).to.equal(true);
		const round1Nonce = aliceChannel.getFullState().localNonce;
		expect(alice.updateChannelFee(channelId, 1500).ok).to.equal(true);

		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(2n);
		expect(bobChannel.getFullState().localCommitmentNumber).to.equal(2n);

		// Each round rotated the current nonce again.
		expect(
			Buffer.from(aliceChannel.getFullState().localNonce!)
		).to.not.deep.equal(
			Buffer.from(round1Nonce!),
			'commitment #2 must use a different verification nonce than #1'
		);

		assertCommitmentAggregates(aliceChannel, 2n);
		assertCommitmentAggregates(bobChannel, 2n);
	});

	it('re-exchanges verification nonces on channel_reestablish and resumes a round', function () {
		this.timeout(20000);
		const { alice, aliceChannel, bobChannel, channelId } =
			setupReadyTaprootChannel();

		// Advance to commitment #1.
		expect(alice.updateChannelFee(channelId, 1000).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);
		expect(bobChannel.getFullState().localCommitmentNumber).to.equal(1n);

		// Simulate a reconnect: the in-memory MuSig2 nonces are lost (never
		// serialized) and the channel re-enters AWAITING_REESTABLISH.
		for (const ch of [aliceChannel, bobChannel]) {
			const s = ch.getFullState();
			s.preReestablishState = s.state;
			s.state = ChannelState.AWAITING_REESTABLISH;
			s.localNonce = undefined;
			s.localNextNonce = undefined;
			s.remoteNonce = undefined;
			s.remoteSigningNonce = undefined;
		}

		// Build BOTH channel_reestablish messages before either is handled (so the
		// loopback can't restore state mid-exchange).
		const extract = (ch: Channel) => {
			const actions = ch.createReestablish();
			const a = actions.find(
				(x) =>
					(x as { messageType?: number }).messageType ===
					MessageType.CHANNEL_REESTABLISH
			) as { payload: Buffer };
			return decodeChannelReestablishMessage(a.payload);
		};
		const aliceMsg = extract(aliceChannel);
		const bobMsg = extract(bobChannel);

		// Each side advertises a fresh 66-byte verification nonce.
		expect(aliceMsg.nextLocalNonce, 'alice advertises a verif nonce').to.exist;
		expect(aliceMsg.nextLocalNonce!.length).to.equal(66);
		expect(bobMsg.nextLocalNonce, 'bob advertises a verif nonce').to.exist;

		// Handle each other's reestablish → adopt the peer nonce + restore NORMAL.
		aliceChannel.handleReestablish(bobMsg);
		bobChannel.handleReestablish(aliceMsg);

		for (const [ch, peerMsg] of [
			[aliceChannel, bobMsg],
			[bobChannel, aliceMsg]
		] as Array<[Channel, typeof aliceMsg]>) {
			const s = ch.getFullState();
			expect(s.state).to.equal(ChannelState.NORMAL);
			expect(Buffer.from(s.remoteNonce!)).to.deep.equal(
				Buffer.from(peerMsg.nextLocalNonce!),
				'remoteNonce must be the peer-advertised reestablish nonce'
			);
			expect(s.localNonce, 'regenerated current nonce').to.exist;
			expect(s.localNextNonce, 'regenerated next nonce').to.exist;
		}

		// GATE: a fresh commitment round completes post-reconnect and both sides'
		// commitment #2 partials aggregate into a valid key-spend signature.
		expect(alice.updateChannelFee(channelId, 1500).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(2n);
		expect(bobChannel.getFullState().localCommitmentNumber).to.equal(2n);
		assertCommitmentAggregates(aliceChannel, 2n);
		assertCommitmentAggregates(bobChannel, 2n);
	});

	it('retransmits the taproot commitment_signed with its real partial_signature_with_nonce (not a zero sig)', function () {
		this.timeout(20000);
		const { alice, aliceChannel, bobChannel, channelId } =
			setupReadyTaprootChannel();

		// Advance to commitment #1 so Alice has a commitment_signed to retransmit
		// and has cached the 98-byte partial it put on the wire.
		expect(alice.updateChannelFee(channelId, 1000).ok).to.equal(true);
		expect(aliceChannel.getFullState().remoteCommitmentNumber).to.equal(1n);

		const cached =
			aliceChannel.getFullState().lastSentPartialSignatureWithNonce;
		expect(cached, 'cached partial_signature_with_nonce').to.exist;
		expect(cached!.length).to.equal(98);

		// Build Bob's channel_reestablish, then rewind nextCommitmentNumber so it
		// looks like Bob never received Alice's commitment #1 — the trigger for the
		// retransmit branch in handleReestablish.
		const reestActions = bobChannel.createReestablish();
		const reestAction = reestActions.find(
			(x) =>
				(x as { messageType?: number }).messageType ===
				MessageType.CHANNEL_REESTABLISH
		) as { payload: Buffer };
		const bobMsg = decodeChannelReestablishMessage(reestAction.payload);
		bobMsg.nextCommitmentNumber = 1n;

		const actions = aliceChannel.handleReestablish(bobMsg);
		const commitAction = actions.find(
			(x) =>
				(x as { messageType?: number }).messageType ===
				MessageType.COMMITMENT_SIGNED
		) as { payload: Buffer } | undefined;
		expect(commitAction, 'a commitment_signed must be retransmitted').to.exist;

		const decoded = decodeCommitmentSignedMessage(commitAction!.payload);
		// The ECDSA signature field stays all-zero for taproot...
		expect(decoded.signature.equals(Buffer.alloc(64))).to.equal(true);
		// ...and the actual signing material rides in the TLV, byte-identical to
		// what Alice originally sent (same nonce — a replay, not a re-sign).
		expect(decoded.partialSignatureWithNonce, 'partial TLV present').to.exist;
		expect(decoded.partialSignatureWithNonce!.length).to.equal(98);
		expect(Buffer.from(decoded.partialSignatureWithNonce!)).to.deep.equal(
			Buffer.from(cached!)
		);
	});

	it('re-derives the SAME verification nonce after a reconnect (deterministic per height)', function () {
		this.timeout(20000);
		const { alice, aliceChannel, channelId } = setupReadyTaprootChannel();

		// Advance to commitment #1 so localNonce is the verification nonce for #1.
		expect(alice.updateChannelFee(channelId, 1000).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);

		const before = aliceChannel.getFullState().localNonce;
		const beforeNext = aliceChannel.getFullState().localNextNonce;
		expect(before, 'localNonce present').to.exist;
		expect(beforeNext, 'localNextNonce present').to.exist;

		// Simulate the reconnect nonce loss, then rebuild via createReestablish.
		const s = aliceChannel.getFullState();
		s.preReestablishState = s.state;
		s.state = ChannelState.AWAITING_REESTABLISH;
		s.localNonce = undefined;
		s.localNextNonce = undefined;
		aliceChannel.createReestablish();

		const after = aliceChannel.getFullState().localNonce;
		const afterNext = aliceChannel.getFullState().localNextNonce;
		expect(after, 're-derived localNonce').to.exist;
		// Deterministic per height: identical bytes to the pre-reconnect nonces.
		expect(Buffer.from(after!)).to.deep.equal(
			Buffer.from(before!),
			'verification nonce for the current commitment must re-derive identically'
		);
		expect(Buffer.from(afterNext!)).to.deep.equal(
			Buffer.from(beforeNext!),
			'next-commitment verification nonce must re-derive identically'
		);
	});

	it('force-closes the PRE-reconnect commitment after a reconnect (deterministic nonce recovery)', function () {
		this.timeout(20000);
		const { alice, aliceChannel, channelId } = setupReadyTaprootChannel();

		// Advance to commitment #1. The peer's partial over our commitment #1
		// (remoteCommitmentSignature) + its signing nonce (remoteSigningNonce) are
		// now stored, made against our verification nonce for height 1.
		expect(alice.updateChannelFee(channelId, 1000).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);

		// Simulate a reconnect that loses the in-memory verification nonces (exactly
		// the scenario that previously made the pre-reconnect commitment
		// un-force-closeable). remoteSigningNonce survives the reconnect in memory.
		const s = aliceChannel.getFullState();
		s.preReestablishState = s.state;
		s.state = ChannelState.AWAITING_REESTABLISH;
		s.localNonce = undefined;
		s.localNextNonce = undefined;
		aliceChannel.createReestablish(); // re-derives the deterministic nonces
		s.state = s.preReestablishState!;
		s.preReestablishState = null;

		// GATE 1: the re-derived current-commitment verification nonce aggregates
		// with the peer's STORED partial (made against the pre-reconnect nonce) into
		// a valid BIP340 key-spend signature over commitment #1. This is exactly the
		// aggregation forceClose performs.
		assertCommitmentAggregates(aliceChannel, 1n);

		// GATE 2: forceClose() itself succeeds (no "missing nonce" error) and emits a
		// broadcastable commitment tx.
		const actions = aliceChannel.forceClose(aliceChannel.getSigner()!);
		const errored = actions.find((a) => a.type === ChannelActionType.ERROR) as
			| { type: ChannelActionType; message: string }
			| undefined;
		expect(errored, errored?.message).to.be.undefined;
		const broadcast = actions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		);
		expect(broadcast, 'force-close must emit a BROADCAST_TX').to.exist;
	});

	it('is reuse-safe: retrying force-close reproduces a byte-identical commitment (deterministic nonce, no second distinct signature)', function () {
		this.timeout(20000);
		const { alice, aliceChannel, channelId } = setupReadyTaprootChannel();

		expect(alice.updateChannelFee(channelId, 1000).ok).to.equal(true);
		expect(aliceChannel.getFullState().localCommitmentNumber).to.equal(1n);

		// SAFETY PROPERTY: the verification nonce for a given commitment height is
		// deterministic and is bound to the SINGLE peer signing nonce stored for
		// that height (remoteSigningNonce). A MuSig2 key leak requires the same
		// secret nonce to sign two DIFFERENT challenges; here a force-close retry
		// re-derives the SAME verification nonce and pairs it with the SAME peer
		// nonce over the SAME commitment, so it must yield the byte-identical
		// signature — never a second, distinct partial. (The library purges the
		// secret nonce after the first sign, so the retry genuinely re-derives.)
		const extractTx = (acts: ReturnType<Channel['forceClose']>): Buffer => {
			const b = acts.find((a) => a.type === ChannelActionType.BROADCAST_TX) as
				| { type: ChannelActionType; tx: Buffer }
				| undefined;
			expect(b, 'force-close must emit a BROADCAST_TX').to.exist;
			return b!.tx;
		};

		const tx1 = extractTx(aliceChannel.forceClose(aliceChannel.getSigner()!));
		// Channel is now FORCE_CLOSED; forceClose is explicitly re-runnable there
		// (the rebroadcast path) and must rebuild the identical transaction.
		const tx2 = extractTx(aliceChannel.forceClose(aliceChannel.getSigner()!));

		expect(Buffer.from(tx1)).to.deep.equal(
			Buffer.from(tx2),
			'a force-close retry must reproduce the byte-identical commitment+witness'
		);
	});
});
