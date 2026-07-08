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

	it('errors when a taproot peer sends shutdown without the nonce TLV', function () {
		const { bobChannel, channelId } = readyTaprootChannel(7, 8);
		const stateBefore = bobChannel.getState();

		const actions = bobChannel.handleShutdown({
			channelId,
			scriptPubkey: P2WPKH_A
		});
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'expected an ERROR action').to.exist;
		expect(err.message).to.match(/nonce/i);
		expect(bobChannel.getState()).to.equal(stateBefore);
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
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'expected an ERROR action').to.exist;
		expect(err.message).to.match(/partial/i);
		expect(bobChannel.getState()).to.not.equal(ChannelState.CLOSED);
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
		const err = actions.find((a) => a.type === ChannelActionType.ERROR) as {
			message: string;
		};
		expect(err, 'expected an ERROR action').to.exist;
		expect(err.message).to.match(/echo/i);
		expect(aliceChannel.getState()).to.not.equal(ChannelState.CLOSED);
	});

	it('responder rejects an unreasonable initiator fee (fund-safety)', function () {
		// bob is the RESPONDER here (alice, the opener, never proposes): a fee
		// far outside the reasonable band must be refused rather than accepted
		// verbatim, since single-round negotiation cannot counter it.
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

		// An absurdly high fee (would burn the balance to miners).
		const high = bobChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 5_000_000n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		expect(
			high.find((a) => a.type === ChannelActionType.ERROR),
			'high fee rejected'
		).to.exist;
		expect(bobChannel.getState()).to.not.equal(ChannelState.CLOSED);

		// An absurdly low fee (would produce an unrelayable, un-RBF-able tx).
		const low = bobChannel.handleClosingSigned(
			{
				channelId,
				feeSatoshis: 1n,
				signature: Buffer.alloc(64),
				partialSignature: crypto.randomBytes(32)
			},
			() => crypto.randomBytes(32)
		);
		expect(
			low.find((a) => a.type === ChannelActionType.ERROR),
			'low fee rejected'
		).to.exist;
		expect(bobChannel.getState()).to.not.equal(ChannelState.CLOSED);
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
