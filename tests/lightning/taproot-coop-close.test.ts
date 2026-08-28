/**
 * Taproot cooperative close (MuSig2 key-spend mutual close).
 *
 * Wire format (pinned against live LND v0.20, simple-taproot channels):
 * - shutdown carries the sender's 66-byte MuSig2 closing nonce as TLV type 8;
 *   every (re)transmitted shutdown starts a fresh closing session.
 * - the legacy closing_signed flow is used (option_simple_close excludes
 *   taproot); closing_signed carries a 32-byte MuSig2 partial signature as
 *   TLV type 6 with the fixed ECDSA field zeroed.
 * - fee negotiation is single-round: the responder accepts the initiator's
 *   first offer verbatim, the initiator errors on any other fee. Each side's
 *   closing nonce therefore signs exactly one sighash.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { taprootCommitmentSighash } from '../../src/lightning/channel/commitment-musig';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Channel } from '../../src/lightning/channel/channel';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeShutdownMessage,
	decodeClosingSignedMessage,
	encodeClosingSignedMessage,
	encodeShutdownMessage
} from '../../src/lightning/message/channel-close';
import { expectWireFailure, wireRefusalOf } from './helpers/open-refusal';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-coop-close-${id}`))
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

interface IWireTap {
	type: number;
	payload: Buffer;
	from: string;
}

function connectManagers(
	a: ChannelManager,
	aPub: string,
	b: ChannelManager,
	bPub: string,
	tap?: IWireTap[]
): void {
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bPub) {
			tap?.push({ type, payload, from: aPub });
			b.handleMessage(aPub, type, payload);
		}
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aPub) {
			tap?.push({ type, payload, from: bPub });
			a.handleMessage(bPub, type, payload);
		}
	});
}

function readyTaprootChannel(
	seedA: number,
	seedB: number,
	tap?: IWireTap[]
): {
	alice: ChannelManager;
	bob: ChannelManager;
	aliceChannel: Channel;
	bobChannel: Channel;
	channelId: Buffer;
	aPub: string;
	bPub: string;
} {
	const alice = new ChannelManager(makeConfig(seedA, true));
	const bob = new ChannelManager(makeConfig(seedB, false));
	// Negative-path tests drive channel ERROR actions; absorb the manager
	// 'error' events so the EventEmitter does not throw them.
	alice.on('error', () => {});
	bob.on('error', () => {});
	const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
	const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
	connectManagers(alice, aPub, bob, bPub, tap);

	// Push 300k sat to bob so both sides have a non-dust closing output.
	const aliceChannel = alice.openChannel(bPub, 1_000_000n, 300_000_000n);
	const channelId = alice.createFunding(
		aliceChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	const bobChannel = bob.getChannel(channelId)!;
	expect(isTaprootChannel(aliceChannel.getFullState().channelType)).to.equal(
		true
	);
	expect(aliceChannel.getFullState().state).to.equal(ChannelState.NORMAL);

	// Both sides need a shutdown script; managers derive a default, but set
	// explicit wallet scripts so the closing outputs are predictable.
	return { alice, bob, aliceChannel, bobChannel, channelId, aPub, bPub };
}

const P2WPKH_A = Buffer.from('0014' + 'aa'.repeat(20), 'hex');

/**
 * Assert the broadcast mutual-close tx spends the MuSig2 funding output with
 * a valid single-signature BIP340 key-spend witness.
 */
function assertCloseTxValid(txBuf: Buffer, channel: Channel): void {
	const state = channel.getFullState();
	const tx = bitcoin.Transaction.fromBuffer(txBuf);
	expect(tx.ins.length).to.equal(1);
	const witness = tx.ins[0].witness;
	expect(witness.length, 'key-spend witness has one element').to.equal(1);
	const sig = witness[0];
	expect(sig.length).to.equal(64);
	// LND builds the taproot coop-close tx RBF-signalled; the sequence is part
	// of the BIP341 sighash, so it is consensus-critical.
	expect(tx.ins[0].sequence).to.equal(0xfffffffd);

	const funding = createTaprootFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey
	);
	const sighash = taprootCommitmentSighash(
		tx,
		funding.p2trOutput,
		Number(state.fundingSatoshis)
	);
	expect(ecc.verifySchnorr(sighash, funding.outputKey, sig)).to.equal(true);

	// Both closing outputs pay the negotiated shutdown scripts.
	const outScripts = tx.outs.map((o) => Buffer.from(o.script).toString('hex'));
	expect(outScripts).to.include(
		Buffer.from(state.localShutdownScript!).toString('hex')
	);
	expect(outScripts).to.include(
		Buffer.from(state.remoteShutdownScript!).toString('hex')
	);
}

describe('Taproot cooperative close (MuSig2)', function () {
	it('closes beignet<->beignet with an aggregated key-spend witness (opener initiates)', function () {
		const tap: IWireTap[] = [];
		const { alice, bob, aliceChannel, bobChannel, channelId } =
			readyTaprootChannel(1, 2, tap);

		const broadcasts: Buffer[] = [];
		alice.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		bob.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		const res = alice.initiateShutdown(channelId, P2WPKH_A);
		expect(res.ok, res.error).to.equal(true);

		// Shutdown exchange: both directions carried a TLV-8 nonce.
		const shutdowns = tap.filter((m) => m.type === MessageType.SHUTDOWN);
		expect(shutdowns.length).to.equal(2);
		for (const s of shutdowns) {
			const decoded = decodeShutdownMessage(s.payload);
			expect(decoded.shutdownNonce, 'shutdown nonce present').to.exist;
			expect(decoded.shutdownNonce!.length).to.equal(66);
		}

		// closing_signed both ways: zeroed ECDSA field + 32B partial, echoed fee.
		const closings = tap
			.filter((m) => m.type === MessageType.CLOSING_SIGNED)
			.map((m) => decodeClosingSignedMessage(m.payload));
		expect(closings.length).to.equal(2);
		for (const c of closings) {
			expect(c.signature).to.deep.equal(Buffer.alloc(64));
			expect(c.partialSignature, 'partial sig TLV present').to.exist;
			expect(c.partialSignature!.length).to.equal(32);
		}
		expect(closings[0].feeSatoshis).to.equal(closings[1].feeSatoshis);

		expect(aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(bobChannel.getState()).to.equal(ChannelState.CLOSED);

		// Both sides broadcast the IDENTICAL fully-signed close tx.
		expect(broadcasts.length).to.equal(2);
		expect(broadcasts[0].equals(broadcasts[1])).to.equal(true);
		assertCloseTxValid(broadcasts[0], aliceChannel);
		assertCloseTxValid(broadcasts[1], bobChannel);
	});

	it('closes when the NON-opener initiates shutdown (opener still proposes the fee)', function () {
		const tap: IWireTap[] = [];
		const { alice, bob, aliceChannel, bobChannel, channelId } =
			readyTaprootChannel(3, 4, tap);

		const broadcasts: Buffer[] = [];
		alice.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		bob.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		const res = bob.initiateShutdown(channelId, P2WPKH_A);
		expect(res.ok, res.error).to.equal(true);

		// Opener (alice) sends the first closing_signed per BOLT 2.
		const firstClosing = tap.find(
			(m) => m.type === MessageType.CLOSING_SIGNED
		)!;
		expect(firstClosing.from).to.equal(
			alice['config'].localBasepoints.fundingPubkey.toString('hex')
		);

		expect(aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(bobChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(broadcasts.length).to.equal(2);
		expect(broadcasts[0].equals(broadcasts[1])).to.equal(true);
		assertCloseTxValid(broadcasts[0], aliceChannel);
	});

	it('ignores option_simple_close for taproot channels (setSimpleClose forced off)', function () {
		const { aliceChannel } = readyTaprootChannel(5, 6);
		aliceChannel.setSimpleClose(true);
		expect(aliceChannel.isSimpleClose()).to.equal(false);
	});

	it('fails the channel on the wire when a taproot peer sends shutdown without the nonce TLV', function () {
		const { bobChannel, channelId } = readyTaprootChannel(7, 8);

		const actions = bobChannel.handleShutdown({
			channelId,
			scriptPubkey: P2WPKH_A
		});
		expectWireFailure(actions, channelId, /nonce/i);
		expect(bobChannel.getState()).to.equal(ChannelState.ERRORED);
		expect(bobChannel.getFullState().remoteShutdownScript).to.not.exist;
	});

	it('errors when closing_signed omits the partial signature TLV', function () {
		const { bobChannel, channelId } = readyTaprootChannel(9, 10);

		// Complete the shutdown exchange at bob (responder), then hand it a
		// closing_signed with no partial-sig TLV: hard error, never treated as
		// an ECDSA fallback.
		bobChannel.handleShutdown(
			{
				channelId,
				scriptPubkey: P2WPKH_A,
				shutdownNonce: crypto.randomBytes(66)
			},
			P2WPKH_A
		);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

		const actions = bobChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 200n,
				signature: crypto.randomBytes(64)
			},
			() => crypto.randomBytes(32)
		);
		expectWireFailure(actions, channelId, /partial/i);
		expect(bobChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	it('initiator errors when the echoed fee differs from its offer', function () {
		const { aliceChannel, channelId } = readyTaprootChannel(13, 14);

		// Alice initiates + proposes for real via the manager wire; then craft a
		// wrong-fee echo directly at the channel.
		// Drive the state machine directly to keep the wire out of the way.
		const shutdownActions = aliceChannel.initiateShutdown(P2WPKH_A);
		expect(
			shutdownActions.some((a) => a.type === ChannelActionType.SEND_MESSAGE)
		).to.equal(true);
		aliceChannel.handleShutdown({
			channelId,
			scriptPubkey: P2WPKH_A,
			shutdownNonce: crypto.randomBytes(66)
		});
		const proposeActions = aliceChannel.proposeClosingFee(() =>
			crypto.randomBytes(32)
		);
		expect(
			proposeActions.some((a) => a.type === ChannelActionType.SEND_MESSAGE)
		).to.equal(true);
		const offered = aliceChannel.getFullState().lastProposedClosingFeeSat!;

		const actions = aliceChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: offered + 10n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		expectWireFailure(actions, channelId, /echo/i);
		expect(aliceChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	// bob is the RESPONDER in the next two (alice, the opener, never proposes):
	// a fee far outside the reasonable band must be refused rather than
	// accepted verbatim, since single-round negotiation cannot counter it.
	// The refusal stays a LOCAL error (issue 409 carve-out): the band comes
	// from OUR private feerate estimate, a fact the peer never held, so a
	// conformant initiator with a fresher fee view can land here on a fee the
	// opener can perfectly well pay. Wire-failing it would force-close over a
	// disagreement grounded in our own estimate.
	it('responder rejects an unreasonably HIGH initiator fee LOCALLY (fund-safety)', function () {
		// An absurdly high fee (would burn the balance to miners).
		const { bobChannel, channelId } = readyTaprootChannel(21, 22);
		bobChannel.handleShutdown(
			{
				channelId,
				scriptPubkey: P2WPKH_A,
				shutdownNonce: crypto.randomBytes(66)
			},
			P2WPKH_A
		);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

		const high = bobChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 5_000_000n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		const err = high.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'high fee rejected').to.exist;
		expect(err.message).to.match(/outside acceptable range/);
		expect(wireRefusalOf(high), 'nothing on the wire').to.equal(null);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
	});

	it('responder rejects an unreasonably LOW initiator fee LOCALLY (fund-safety)', function () {
		// An absurdly low fee (would produce an unrelayable, un-RBF-able tx).
		const { bobChannel, channelId } = readyTaprootChannel(43, 44);
		bobChannel.handleShutdown(
			{
				channelId,
				scriptPubkey: P2WPKH_A,
				shutdownNonce: crypto.randomBytes(66)
			},
			P2WPKH_A
		);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

		const low = bobChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 1n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		const err = low.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'low fee rejected').to.exist;
		expect(err.message).to.match(/outside acceptable range/);
		expect(wireRefusalOf(low), 'nothing on the wire').to.equal(null);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
	});

	it('responder rejects an in-band fee below the min-relay floor (issue #579)', function () {
		// The band floor is ideal/5, i.e. 0.2 sat/vB at the 253 sat/kw anchor
		// floor. Single-round negotiation means accepting IS closing, so a fee
		// in that gap put us in CLOSED holding a tx no mempool takes, with only
		// the peer (whose output pays the fee) able to replace it.
		const { bobChannel, channelId } = readyTaprootChannel(63, 64);
		bobChannel.handleShutdown(
			{
				channelId,
				scriptPubkey: P2WPKH_A,
				shutdownNonce: crypto.randomBytes(66)
			},
			P2WPKH_A
		);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

		// 100 sat is well above ideal/5 (26 sat) but pays 0.77 sat/vB on the
		// 130-vbyte taproot closing tx.
		const actions = bobChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 100n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'sub-relay fee rejected').to.exist;
		expect(err.message).to.match(/outside acceptable range \[130,/);
		expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
	});

	it('responder rejects a fee exceeding the opener balance', function () {
		// bob (non-opener responder): the fee comes out of ALICE's output, and a
		// fee above her whole balance can never produce a valid closing tx. The
		// band is [ideal/5, ideal*5], so shrink alice's mirrored balance below
		// the band floor to reach the exceeds-balance arm with an in-band fee.
		const { bobChannel, channelId } = readyTaprootChannel(45, 46);
		bobChannel.handleShutdown(
			{
				channelId,
				scriptPubkey: P2WPKH_A,
				shutdownNonce: crypto.randomBytes(66)
			},
			P2WPKH_A
		);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

		bobChannel.getFullState().remoteBalanceMsat = 100_000n; // 100 sat
		const actions = bobChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 200n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		expectWireFailure(actions, channelId, /exceeds opener balance/);
		expect(bobChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	it('responder fails the channel on a partial that does not verify', function () {
		const { bobChannel, channelId } = readyTaprootChannel(47, 48);
		bobChannel.handleShutdown(
			{
				channelId,
				scriptPubkey: P2WPKH_A,
				shutdownNonce: crypto.randomBytes(66)
			},
			P2WPKH_A
		);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

		const actions = bobChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 200n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32),
			() => false
		);
		expectWireFailure(actions, channelId, /partial signature failed to verify/);
		expect(bobChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	it('a close-build failure rolls the channel back instead of stranding it CLOSED', function () {
		// The channel commits CLOSED internally before the manager builds the
		// broadcastable tx; when the guarded build returns null (issue 415's
		// defense in depth), a bare CHANNEL_CLOSED filter left the channel
		// falsely CLOSED with nothing broadcast and no recovery route (issue
		// 409 review, finding 4). It must roll back to NEGOTIATING_CLOSING.
		const { alice, bob, bobChannel, channelId } = readyTaprootChannel(51, 52);
		const bobBroadcasts: Buffer[] = [];
		const bobClosed: Buffer[] = [];
		bob.on('broadcast:tx', (tx: Buffer) => bobBroadcasts.push(tx));
		bob.on('channel:closed', (id: Buffer) => bobClosed.push(id));
		// Fault injection: bob cannot assemble the close tx.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(bob as any).buildSignedMutualCloseTx = (): null => null;

		alice.initiateShutdown(channelId, P2WPKH_A);

		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
		expect(bobBroadcasts.length, 'nothing broadcast by bob').to.equal(0);
		expect(bobClosed.length, 'no channel:closed from bob').to.equal(0);
	});

	it('an UNDECODABLE shutdown (65-byte nonce TLV) fails the channel on the wire', function () {
		// The decoder throws on a wrong-length TLV before handleShutdown can
		// run its own length check, and the throw used to die in
		// handleMessage's catch as a null-id local error (issue 409 review,
		// finding 5). The manager now scopes the failure to the channel id at
		// the payload's fixed offset and puts the refusal on the wire.
		const tap: IWireTap[] = [];
		const { bob, bobChannel, channelId, aPub, bPub } = readyTaprootChannel(
			53,
			54,
			tap
		);
		const raw = Buffer.concat([
			channelId,
			Buffer.from([0, P2WPKH_A.length]),
			P2WPKH_A,
			Buffer.from([8, 65]), // TLV type 8, length 65: one byte short
			Buffer.alloc(65, 1)
		]);
		bob.handleMessage(aPub, MessageType.SHUTDOWN, raw);

		expect(bobChannel.getState()).to.equal(ChannelState.ERRORED);
		const wireError = tap.find(
			(m) => m.from === bPub && m.type === MessageType.ERROR
		);
		expect(wireError, 'wire error sent to the peer').to.exist;
	});

	it('an UNDECODABLE closing_signed (31-byte partial TLV) fails the channel on the wire', function () {
		const tap: IWireTap[] = [];
		const { bob, bobChannel, channelId, aPub, bPub } = readyTaprootChannel(
			55,
			56,
			tap
		);
		const fixed = Buffer.alloc(104); // channel_id + fee + zeroed ECDSA sig
		channelId.copy(fixed, 0);
		fixed.writeBigUInt64BE(200n, 32);
		const raw = Buffer.concat([
			fixed,
			Buffer.from([6, 31]), // TLV type 6, length 31: one byte short
			Buffer.alloc(31, 1)
		]);
		bob.handleMessage(aPub, MessageType.CLOSING_SIGNED, raw);

		expect(bobChannel.getState()).to.equal(ChannelState.ERRORED);
		const wireError = tap.find(
			(m) => m.from === bPub && m.type === MessageType.ERROR
		);
		expect(wireError, 'wire error sent to the peer').to.exist;
	});

	it('control: closing_signed before the nonce exchange stays a LOCAL error', function () {
		// The nonce-exchange-incomplete arm is an argued carve-out: the nonces
		// are unpersisted privates and buildShutdownRetransmit deliberately
		// nulls the remote one on reestablish, so this can fire on ordering
		// artifacts, never provable peer divergence. It must stay off the wire.
		const { aliceChannel, channelId } = readyTaprootChannel(49, 50);
		aliceChannel.initiateShutdown(P2WPKH_A);
		aliceChannel.handleShutdown({
			channelId,
			scriptPubkey: P2WPKH_A,
			shutdownNonce: crypto.randomBytes(66)
		});
		// Reestablish path: the retransmit drops the stale remote nonce.
		aliceChannel.buildShutdownRetransmit();

		const actions = aliceChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 200n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'expected a local ERROR').to.exist;
		expect(err.message).to.match(/nonce exchange/);
		expect(wireRefusalOf(actions), 'nothing on the wire').to.equal(null);
		expect(aliceChannel.getState()).to.not.equal(ChannelState.ERRORED);
	});

	// FS-5: when WE are the opener the closing fee is paid from OUR output. The
	// responder branch must reserve our dust limit (as the legacy fee-range path
	// does) so an adversarial non-opener cannot send closing_signed with a fee
	// that drops our output, burning the balance to miners.
	function driveOpenerIntoResponderBranch(): {
		aliceChannel: Channel;
		channelId: Buffer;
		idealFee: bigint;
		dust: bigint;
	} {
		const { aliceChannel, channelId } = readyTaprootChannel(41, 42);
		// Alice (opener) receives the peer's shutdown and is driven into the
		// responder branch without ever proposing a fee - the in-flight-HTLC case
		// where the opener-proposes-first trigger never fired.
		aliceChannel.handleShutdown(
			{
				channelId,
				scriptPubkey: P2WPKH_A,
				shutdownNonce: crypto.randomBytes(66)
			},
			P2WPKH_A
		);
		expect(aliceChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);

		const st = aliceChannel.getFullState();
		const rate = BigInt(
			Math.max(
				st.localConfig.feeratePerKw || 253,
				st.remoteConfig.feeratePerKw || 253,
				253
			)
		);
		const localLen = BigInt(st.localShutdownScript?.length ?? 22);
		const remoteLen = BigInt(st.remoteShutdownScript?.length ?? 22);
		const bandWeight =
			206n + 4n * (9n + localLen) + 4n * (9n + remoteLen) + 66n;
		const idealFee = (bandWeight * rate + 999n) / 1000n;
		return {
			aliceChannel,
			channelId,
			idealFee,
			dust: st.localConfig.dustLimitSatoshis
		};
	}

	it('responder-as-opener rejects an in-band fee that leaves our output below dust (FS-5)', function () {
		const { aliceChannel, channelId, idealFee, dust } =
			driveOpenerIntoResponderBranch();
		// Our whole balance is one sat short of covering fee + dust, so a normal
		// (mid-band) fee would push our output below the dust limit.
		aliceChannel.getFullState().localBalanceMsat =
			(idealFee + dust - 1n) * 1000n;

		const actions = aliceChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: idealFee,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		expectWireFailure(actions, channelId, /dust/i);
		expect(aliceChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	it('responder-as-opener accepts a fee that leaves exactly the dust reserve', function () {
		const { aliceChannel, channelId, idealFee, dust } =
			driveOpenerIntoResponderBranch();
		aliceChannel.getFullState().localBalanceMsat = (idealFee + dust) * 1000n;

		const actions = aliceChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: idealFee,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		expect(
			actions.find((a) => a.type === ChannelActionType.ERROR),
			'exactly-dust-reserve fee is accepted'
		).to.not.exist;
		expect(aliceChannel.getState()).to.equal(ChannelState.CLOSED);
	});

	it('ignores a same-connection duplicate shutdown after signing (no wedge)', function () {
		// After we (opener) propose and sign with our closing nonce, a duplicate
		// shutdown with a fresh peer nonce on the SAME connection must NOT reset
		// our sign-once latch (which would strand us with a spent local nonce).
		const { aliceChannel, channelId } = readyTaprootChannel(23, 24);
		aliceChannel.initiateShutdown(P2WPKH_A);
		aliceChannel.handleShutdown({
			channelId,
			scriptPubkey: P2WPKH_A,
			shutdownNonce: crypto.randomBytes(66)
		});
		aliceChannel.proposeClosingFee(() => crypto.randomBytes(32));
		const before = aliceChannel.getFullState().lastProposedClosingFeeSat;

		// Duplicate shutdown, fresh nonce, same connection.
		const actions = aliceChannel.handleShutdown({
			channelId,
			scriptPubkey: P2WPKH_A,
			shutdownNonce: crypto.randomBytes(66)
		});
		expect(actions).to.deep.equal([]);
		// Our signed proposal is intact (not reset).
		expect(aliceChannel.getFullState().lastProposedClosingFeeSat).to.equal(
			before
		);
	});

	it('never signs twice in one closing session (sign-once latch)', function () {
		const { aliceChannel, channelId } = readyTaprootChannel(15, 16);
		aliceChannel.initiateShutdown(P2WPKH_A);
		aliceChannel.handleShutdown({
			channelId,
			scriptPubkey: P2WPKH_A,
			shutdownNonce: crypto.randomBytes(66)
		});

		let signCalls = 0;
		const signFn = (): Buffer => {
			signCalls++;
			return crypto.randomBytes(32);
		};
		const first = aliceChannel.proposeClosingFee(signFn);
		expect(
			first.some((a) => a.type === ChannelActionType.SEND_MESSAGE)
		).to.equal(true);
		// Second proposal in the same session: quiet no-op, no second signature.
		const second = aliceChannel.proposeClosingFee(signFn);
		expect(second).to.deep.equal([]);
		expect(signCalls).to.equal(1);
	});

	it('a bad peer partial does not close the channel or broadcast', function () {
		const tap: IWireTap[] = [];
		const { alice, bob, aliceChannel, bobChannel, channelId, bPub } =
			readyTaprootChannel(17, 18, tap);

		const broadcasts: Buffer[] = [];
		alice.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		bob.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		// Intercept alice's closing_signed and corrupt the partial before it
		// reaches bob: detach the auto-wire first.
		alice.removeAllListeners('message:outbound');
		alice.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== bPub) return;
				if (type === MessageType.CLOSING_SIGNED) {
					const msg = decodeClosingSignedMessage(payload);
					msg.partialSignature = crypto.randomBytes(32);
					bob.handleMessage(
						alice['config'].localBasepoints.fundingPubkey.toString('hex'),
						type,
						encodeClosingSignedMessage(msg)
					);
					return;
				}
				bob.handleMessage(
					alice['config'].localBasepoints.fundingPubkey.toString('hex'),
					type,
					payload
				);
			}
		);

		alice.initiateShutdown(channelId, P2WPKH_A);

		expect(bobChannel.getState()).to.not.equal(ChannelState.CLOSED);
		expect(aliceChannel.getState()).to.not.equal(ChannelState.CLOSED);
		expect(broadcasts.length).to.equal(0);
	});

	it('completes the close after a shutdown retransmission (fresh nonces, reestablish path)', function () {
		const tap: IWireTap[] = [];
		const { alice, bob, aliceChannel, bobChannel, channelId, aPub, bPub } =
			readyTaprootChannel(19, 20, tap);

		// Freeze the wire mid-negotiation: detach bob's auto-delivery so
		// alice's first closing_signed is LOST after the shutdown exchange.
		alice.removeAllListeners('message:outbound');
		const lost: IWireTap[] = [];
		alice.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== bPub) return;
				if (type === MessageType.CLOSING_SIGNED) {
					lost.push({ type, payload, from: aPub });
					return; // dropped: simulates disconnect mid-negotiation
				}
				bob.handleMessage(aPub, type, payload);
			}
		);

		alice.initiateShutdown(channelId, P2WPKH_A);
		expect(aliceChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
		expect(bobChannel.getState()).to.equal(ChannelState.NEGOTIATING_CLOSING);
		expect(lost.length, 'first closing_signed was dropped').to.equal(1);

		// "Reconnect": restore full delivery, then both sides retransmit
		// shutdown with FRESH nonces (what the manager does after reestablish).
		alice.removeAllListeners('message:outbound');
		connectManagers(alice, aPub, bob, bPub, tap);

		const broadcasts: Buffer[] = [];
		alice.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
		bob.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));

		const aliceRetransmit = aliceChannel.buildShutdownRetransmit();
		const bobRetransmit = bobChannel.buildShutdownRetransmit();
		expect(aliceRetransmit.shutdownNonce!.length).to.equal(66);
		expect(bobRetransmit.shutdownNonce!.length).to.equal(66);

		// Cross-deliver the retransmitted shutdowns: bob (responder) receives
		// alice's FIRST — mirroring the wire, where the opener's shutdown always
		// precedes its closing_signed on the same connection — then alice
		// receives bob's fresh nonce and re-proposes; the close completes.
		bob.handleMessage(
			aPub,
			MessageType.SHUTDOWN,
			encodeShutdownMessage(aliceRetransmit)
		);
		alice.handleMessage(
			bPub,
			MessageType.SHUTDOWN,
			encodeShutdownMessage(bobRetransmit)
		);

		expect(aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(bobChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(broadcasts.length).to.equal(2);
		expect(broadcasts[0].equals(broadcasts[1])).to.equal(true);
		assertCloseTxValid(broadcasts[0], aliceChannel);
	});
});
