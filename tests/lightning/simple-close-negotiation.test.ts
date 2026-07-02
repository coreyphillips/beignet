/**
 * option_simple_close negotiation: two ChannelManagers with real signers drive
 * shutdown → closing_complete → closing_sig → CLOSED, with the broadcast tx's
 * funding witness cryptographically verified. Fund-safety negatives assert
 * that no bad message can reach CLOSED or produce a broadcast.
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
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	IClosingCompleteMessage,
	encodeClosingCompleteMessage,
	encodeClosingSigMessage,
	decodeClosingCompleteMessage
} from '../../src/lightning/message/channel-close';
import { createFundingScript } from '../../src/lightning/script/funding';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Channel } from '../../src/lightning/channel/channel';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`simple-close-seed-${id}`))
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

function simpleCloseFeatures(): FeatureFlags {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.SHUTDOWN_ANY_SEGWIT);
	flags.setOptional(Feature.SIMPLE_CLOSE);
	return flags;
}

function makeConfig(
	seedId: number,
	simpleClose: boolean
): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey,
		localFeatures: simpleClose ? simpleCloseFeatures() : FeatureFlags.empty()
	};
}

/** Stub peer manager exposing only the remote init features. */
function stubPeers(
	manager: ChannelManager,
	remoteFeatures: FeatureFlags
): void {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(manager as any)['peerManager'] = {
		getPeer: () => ({
			getRemoteInit: () => ({ features: remoteFeatures })
		})
	};
}

interface IOutMsg {
	peer: string;
	type: number;
	payload: Buffer;
}

/** Queue outbound messages instead of auto-delivering (manual pumping). */
function collectOutbound(manager: ChannelManager): IOutMsg[] {
	const queue: IOutMsg[] = [];
	manager.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			queue.push({ peer, type, payload });
		}
	);
	return queue;
}

function collectBroadcasts(manager: ChannelManager): Buffer[] {
	const txs: Buffer[] = [];
	manager.on('broadcast:tx', (tx: Buffer) => txs.push(tx));
	return txs;
}

/** Deliver all queued messages from `queue` to `to`, draining the queue. */
function pump(queue: IOutMsg[], to: ChannelManager, fromPub: string): void {
	while (queue.length > 0) {
		const m = queue.shift()!;
		to.handleMessage(fromPub, m.type, m.payload);
	}
}

const ALICE_SCRIPT = Buffer.from('0014' + 'aa'.repeat(20), 'hex');

interface IHarness {
	alice: ChannelManager;
	bob: ChannelManager;
	aPub: string;
	bPub: string;
	aliceOut: IOutMsg[];
	bobOut: IOutMsg[];
	aliceTxs: Buffer[];
	bobTxs: Buffer[];
	aliceChannel: Channel;
	bobChannel: Channel;
	channelId: Buffer;
}

/**
 * Open a 1M-sat channel alice→bob (optionally pushing sats to bob) between
 * two managers that negotiated option_simple_close, with manual message
 * pumping so tests control delivery order.
 */
function openChannelHarness(
	seedA: number,
	seedB: number,
	pushMsat: bigint,
	simpleClose = true
): IHarness {
	const alice = new ChannelManager(makeConfig(seedA, simpleClose));
	const bob = new ChannelManager(makeConfig(seedB, simpleClose));
	const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
	const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
	const remoteFeatures = simpleClose
		? simpleCloseFeatures()
		: FeatureFlags.empty();
	stubPeers(alice, remoteFeatures);
	stubPeers(bob, remoteFeatures);

	const aliceOut = collectOutbound(alice);
	const bobOut = collectOutbound(bob);
	const aliceTxs = collectBroadcasts(alice);
	const bobTxs = collectBroadcasts(bob);

	const aliceChannel = alice.openChannel(bPub, 1_000_000n, pushMsat);
	pump(aliceOut, bob, aPub); // open_channel
	pump(bobOut, alice, bPub); // accept_channel
	const channelId = alice.createFunding(
		aliceChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	pump(aliceOut, bob, aPub); // funding_created
	pump(bobOut, alice, bPub); // funding_signed
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	pump(aliceOut, bob, aPub); // channel_ready
	pump(bobOut, alice, bPub); // channel_ready

	const bobChannel = bob.getChannel(channelId)!;
	expect(aliceChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(bobChannel.getState()).to.equal(ChannelState.NORMAL);
	return {
		alice,
		bob,
		aPub,
		bPub,
		aliceOut,
		bobOut,
		aliceTxs,
		bobTxs,
		aliceChannel,
		bobChannel,
		channelId
	};
}

/** Verify both funding-witness signatures on a broadcast closing tx. */
function verifyCloseTxWitness(
	txBytes: Buffer,
	aliceFundingPub: Buffer,
	bobFundingPub: Buffer,
	fundingSats: number
): bitcoin.Transaction {
	const tx = bitcoin.Transaction.fromBuffer(txBytes);
	const witness = tx.ins[0].witness;
	expect(witness.length, '2-of-2 witness stack').to.equal(4);
	expect(witness[0].length).to.equal(0);

	const { witnessScript } = createFundingScript(aliceFundingPub, bobFundingPub);
	expect(witness[3].equals(witnessScript), 'funding witness script').to.equal(
		true
	);

	const sighash = tx.hashForWitnessV0(
		0,
		witnessScript,
		fundingSats,
		bitcoin.Transaction.SIGHASH_ALL
	);
	const sortedPubs = [aliceFundingPub, bobFundingPub].sort(Buffer.compare);
	for (let i = 0; i < 2; i++) {
		const decoded = bitcoin.script.signature.decode(witness[1 + i]);
		expect(decoded.hashType).to.equal(bitcoin.Transaction.SIGHASH_ALL);
		expect(
			ecc.verify(sighash, sortedPubs[i], decoded.signature),
			`signature ${i} verifies against sorted pubkey ${i}`
		).to.equal(true);
	}
	expect(tx.version).to.equal(2);
	expect(tx.ins[0].sequence).to.equal(0xfffffffd);
	return tx;
}

describe('option_simple_close negotiation (ChannelManager)', function () {
	it('closes cleanly: shutdown → closing_complete → closing_sig → CLOSED + verified broadcast', function () {
		const h = openChannelHarness(1, 2, 400_000_000n); // bob gets 400k sat

		expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
			true
		);
		pump(h.aliceOut, h.bob, h.aPub); // shutdown
		// Bob replies shutdown and, being funded, sends his own closing_complete.
		const bobMsgs = h.bobOut.map((m) => m.type);
		expect(bobMsgs).to.include(MessageType.SHUTDOWN);
		expect(bobMsgs).to.include(MessageType.CLOSING_COMPLETE);

		// Bob is the lesser-funded side → must offer ONLY closer_and_closee.
		const bobCC = decodeClosingCompleteMessage(
			h.bobOut.find((m) => m.type === MessageType.CLOSING_COMPLETE)!.payload
		);
		expect(bobCC.closerAndCloseeSig).to.exist;
		expect(bobCC.closerOutputOnlySig).to.equal(undefined);
		expect(bobCC.closeeOutputOnlySig).to.equal(undefined);

		pump(h.bobOut, h.alice, h.bPub); // shutdown echo + bob's closing_complete
		// Alice: NEGOTIATING → sends her closing_complete (greater-funded: TLVs 1+3),
		// and answers bob's round with closing_sig (closee).
		const aliceCC = decodeClosingCompleteMessage(
			h.aliceOut.find((m) => m.type === MessageType.CLOSING_COMPLETE)!.payload
		);
		expect(aliceCC.closerOutputOnlySig).to.exist;
		expect(aliceCC.closerAndCloseeSig).to.exist;
		expect(h.aliceOut.some((m) => m.type === MessageType.CLOSING_SIG)).to.equal(
			true
		);

		pump(h.aliceOut, h.bob, h.aPub); // closing_complete + closing_sig
		pump(h.bobOut, h.alice, h.bPub); // bob's closing_sig for alice's round

		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(h.bobChannel.getState()).to.equal(ChannelState.CLOSED);

		// Both sides broadcast: each broadcasts the tx of every completed round.
		expect(h.aliceTxs.length).to.be.greaterThan(0);
		expect(h.bobTxs.length).to.be.greaterThan(0);

		const aliceState = h.aliceChannel.getFullState();
		const aPubKey = aliceState.localBasepoints.fundingPubkey;
		const bPubKey = aliceState.remoteBasepoints!.fundingPubkey;
		for (const txBytes of [...h.aliceTxs, ...h.bobTxs]) {
			const tx = verifyCloseTxWitness(txBytes, aPubKey, bPubKey, 1_000_000);
			// Both outputs present (both balances well above dust) and the closer
			// paid the fee: total out < 1M, bob's output untouched in alice's round.
			expect(tx.outs.length).to.equal(2);
			const total = tx.outs.reduce((s, o) => s + o.value, 0);
			expect(total).to.be.lessThan(1_000_000);
		}
	});

	it('omits a dust closee output (closer_output_only) and still closes', function () {
		const h = openChannelHarness(3, 4, 100_000n); // bob gets 100 sat → dust

		expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
			true
		);
		pump(h.aliceOut, h.bob, h.aPub);
		// Bob can't fund a close (100 sat < fee) → no closing_complete from bob.
		expect(
			h.bobOut.some((m) => m.type === MessageType.CLOSING_COMPLETE)
		).to.equal(false);
		pump(h.bobOut, h.alice, h.bPub);

		const aliceCC = decodeClosingCompleteMessage(
			h.aliceOut.find((m) => m.type === MessageType.CLOSING_COMPLETE)!.payload
		);
		expect(aliceCC.closerOutputOnlySig).to.exist;
		expect(aliceCC.closerAndCloseeSig).to.equal(undefined);

		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);

		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(h.bobChannel.getState()).to.equal(ChannelState.CLOSED);
		const aliceState = h.aliceChannel.getFullState();
		const tx = verifyCloseTxWitness(
			h.bobTxs[0],
			aliceState.localBasepoints.fundingPubkey,
			aliceState.remoteBasepoints!.fundingPubkey,
			1_000_000
		);
		expect(tx.outs.length).to.equal(1);
		expect(
			(tx.outs[0].script as Buffer).equals(ALICE_SCRIPT),
			'sole output pays the closer (alice)'
		).to.equal(true);
	});

	describe('fund-safety negatives', function () {
		/** Drive both sides into NEGOTIATING_CLOSING with alice's round pending. */
		function negotiatingHarness(seedA: number, seedB: number): IHarness {
			const h = openChannelHarness(seedA, seedB, 400_000_000n);
			expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
				true
			);
			pump(h.aliceOut, h.bob, h.aPub); // shutdown
			// Deliver ONLY bob's shutdown echo (hold back his closing_complete)
			// so both sit in NEGOTIATING_CLOSING with full control of what's next.
			const shutdownEcho = h.bobOut.find(
				(m) => m.type === MessageType.SHUTDOWN
			)!;
			h.bobOut.length = 0;
			h.alice.handleMessage(h.bPub, shutdownEcho.type, shutdownEcho.payload);
			expect(h.aliceChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
			expect(h.bobChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
			return h;
		}

		function craftedClosingComplete(
			h: IHarness,
			overrides: Partial<IClosingCompleteMessage>
		): Buffer {
			// A closing_complete "from alice" (closer=alice) as bob expects it.
			const bobState = h.bobChannel.getFullState();
			return encodeClosingCompleteMessage({
				channelId: h.channelId,
				closerScriptPubkey: ALICE_SCRIPT,
				closeeScriptPubkey: bobState.localShutdownScript!,
				feeSatoshis: 700n,
				locktime: 0,
				closerAndCloseeSig: crypto.randomBytes(64),
				...overrides
			});
		}

		it('garbage signature in closing_complete → no CLOSED, no broadcast, no closing_sig', function () {
			const h = negotiatingHarness(5, 6);
			const errors: string[] = [];
			h.bob.on('error', (_id, msg: string) => errors.push(msg));

			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, {})
			);

			expect(h.bobChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
			expect(h.bobTxs.length).to.equal(0);
			expect(h.bobOut.some((m) => m.type === MessageType.CLOSING_SIG)).to.equal(
				false
			);
			expect(errors.some((e) => /signature failed to verify/.test(e))).to.equal(
				true
			);

			// Recovery: the real closing_complete from alice still closes cleanly.
			pump(h.aliceOut, h.bob, h.aPub);
			pump(h.bobOut, h.alice, h.bPub);
			expect(h.bobChannel.getState()).to.equal(ChannelState.CLOSED);
			expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		});

		it('fee exceeding the closer balance is rejected', function () {
			const h = negotiatingHarness(7, 8);
			const errors: string[] = [];
			h.bob.on('error', (_id, msg: string) => errors.push(msg));

			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, { feeSatoshis: 700_000n }) // alice has 600k
			);
			expect(h.bobChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
			expect(errors.some((e) => /fee exceeds closer balance/.test(e))).to.equal(
				true
			);
			expect(h.bobTxs.length).to.equal(0);
		});

		it('closee script mismatch is rejected', function () {
			const h = negotiatingHarness(9, 10);
			const errors: string[] = [];
			h.bob.on('error', (_id, msg: string) => errors.push(msg));

			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, {
					closeeScriptPubkey: Buffer.from('0014' + 'cc'.repeat(20), 'hex')
				})
			);
			expect(
				errors.some((e) => /closee script does not match/.test(e))
			).to.equal(true);
			expect(h.bobChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
		});

		it('refuses closer_output_only when our output is not dust', function () {
			const h = negotiatingHarness(11, 12);
			const errors: string[] = [];
			h.bob.on('error', (_id, msg: string) => errors.push(msg));

			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, {
					closerAndCloseeSig: undefined,
					closerOutputOnlySig: crypto.randomBytes(64)
				})
			);
			expect(
				errors.some((e) => /closer_output_only for our non-dust output/.test(e))
			).to.equal(true);
			expect(h.bobChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
			expect(h.bobTxs.length).to.equal(0);
		});

		it('closing_sig that does not echo our closing_complete is rejected', function () {
			const h = negotiatingHarness(13, 14);
			// Alice sent her closing_complete inside negotiatingHarness (queued).
			const aliceCCRaw = h.aliceOut.find(
				(m) => m.type === MessageType.CLOSING_COMPLETE
			)!;
			const aliceCC = decodeClosingCompleteMessage(aliceCCRaw.payload);

			const errors: string[] = [];
			h.alice.on('error', (_id, msg: string) => errors.push(msg));

			// Wrong fee echo
			h.alice.handleMessage(
				h.bPub,
				MessageType.CLOSING_SIG,
				encodeClosingSigMessage({
					...aliceCC,
					feeSatoshis: aliceCC.feeSatoshis + 1n,
					closerOutputOnlySig: undefined,
					closeeOutputOnlySig: undefined,
					closerAndCloseeSig: crypto.randomBytes(64)
				})
			);
			expect(errors.some((e) => /does not echo/.test(e))).to.equal(true);
			expect(h.aliceChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);

			// Two signatures in one closing_sig
			h.alice.handleMessage(
				h.bPub,
				MessageType.CLOSING_SIG,
				encodeClosingSigMessage({
					...aliceCC,
					closerOutputOnlySig: crypto.randomBytes(64),
					closerAndCloseeSig: crypto.randomBytes(64)
				})
			);
			expect(errors.some((e) => /exactly one signature/.test(e))).to.equal(
				true
			);

			// A variant we never offered (alice sent 1+3; craft a type-2 echo)
			h.alice.handleMessage(
				h.bPub,
				MessageType.CLOSING_SIG,
				encodeClosingSigMessage({
					...aliceCC,
					closerOutputOnlySig: undefined,
					closeeOutputOnlySig: crypto.randomBytes(64),
					closerAndCloseeSig: undefined
				})
			);
			expect(errors.some((e) => /not offered by us/.test(e))).to.equal(true);

			expect(h.aliceChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
			expect(h.aliceTxs.length).to.equal(0);
		});

		it('blocks a second closing_complete while awaiting closing_sig (RBF gate)', function () {
			const h = negotiatingHarness(15, 16);
			h.alice.on('error', () => {}); // guard emits error; observed via result
			// Alice already has a closing_complete in flight.
			const result = h.alice.bumpCloseFee(h.channelId, 10_000n);
			expect(result.ok).to.equal(false);
			expect(result.error).to.match(/awaiting closing_sig/);
		});
	});

	it('restarts negotiation after reestablish: shutdown retransmit + fresh closing_complete', function () {
		const h = openChannelHarness(21, 22, 400_000_000n);
		// The duplicated reestablish (manual + manager retransmit) abandons one
		// in-flight round per side; its late closing_sig is rejected with a
		// benign error while the close completes through the other direction.
		h.alice.on('error', () => {});
		h.bob.on('error', () => {});
		expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
			true
		);
		pump(h.aliceOut, h.bob, h.aPub);
		const shutdownEcho = h.bobOut.find((m) => m.type === MessageType.SHUTDOWN)!;
		h.bobOut.length = 0; // hold back bob's closing_complete
		h.alice.handleMessage(h.bPub, shutdownEcho.type, shutdownEcho.payload);
		expect(h.aliceChannel.getFullState().awaitingClosingSig).to.equal(true);
		h.aliceOut.length = 0; // alice's in-flight closing_complete is "lost"

		// Disconnect + reconnect
		h.aliceChannel.markForReestablish();
		h.bobChannel.markForReestablish();
		const aliceRe = h.aliceChannel.createReestablish();
		const bobRe = h.bobChannel.createReestablish();
		const reMsg = (actions: ReturnType<Channel['createReestablish']>): Buffer =>
			(actions.find((a) => 'payload' in a) as { payload: Buffer }).payload;

		h.alice.handleMessage(
			h.bPub,
			MessageType.CHANNEL_REESTABLISH,
			reMsg(bobRe)
		);
		h.bob.handleMessage(
			h.aPub,
			MessageType.CHANNEL_REESTABLISH,
			reMsg(aliceRe)
		);

		// Alice retransmitted shutdown and restarted with a fresh closing_complete
		// (the abandoned round was cleared, so the same fee is allowed again).
		expect(h.aliceOut.some((m) => m.type === MessageType.SHUTDOWN)).to.equal(
			true
		);
		expect(
			h.aliceOut.some((m) => m.type === MessageType.CLOSING_COMPLETE)
		).to.equal(true);

		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(h.bobChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(h.aliceTxs.length).to.be.greaterThan(0);
	});

	it('falls back to legacy closing_signed when the peer lacks the feature', function () {
		const h = openChannelHarness(17, 18, 400_000_000n, false);

		expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
			true
		);
		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		// Legacy negotiation converges over closing_signed messages only.
		let guard = 0;
		while ((h.aliceOut.length > 0 || h.bobOut.length > 0) && guard++ < 20) {
			pump(h.aliceOut, h.bob, h.aPub);
			pump(h.bobOut, h.alice, h.bPub);
		}
		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(h.bobChannel.getState()).to.equal(ChannelState.CLOSED);
	});

	it('serialization round-trips the simple-close fields (and old blobs stay legacy)', function () {
		const h = openChannelHarness(19, 20, 400_000_000n);
		expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
			true
		);
		pump(h.aliceOut, h.bob, h.aPub);
		const shutdownEcho = h.bobOut.find((m) => m.type === MessageType.SHUTDOWN)!;
		h.alice.handleMessage(h.bPub, shutdownEcho.type, shutdownEcho.payload);

		const state = h.aliceChannel.getFullState();
		expect(state.simpleClose).to.equal(true);
		expect(state.lastLocalClosingComplete).to.not.equal(null);
		expect(state.awaitingClosingSig).to.equal(true);

		const restored = deserializeChannelState(serializeChannelState(state));
		expect(restored.simpleClose).to.equal(true);
		expect(restored.lastLocalClosingComplete!.feeSatoshis).to.equal(
			state.lastLocalClosingComplete!.feeSatoshis
		);
		expect(
			restored.lastLocalClosingComplete!.closerScript.equals(
				state.lastLocalClosingComplete!.closerScript
			)
		).to.equal(true);
		expect(restored.lastLocalClosingComplete!.sentVariants).to.deep.equal(
			state.lastLocalClosingComplete!.sentVariants
		);
		// awaitingClosingSig intentionally resets across restart
		expect(restored.awaitingClosingSig).to.equal(false);

		// Old blob (fields absent) → legacy defaults
		const serialized = serializeChannelState(state);
		delete serialized.simpleClose;
		delete serialized.lastCloseFeeSat;
		delete serialized.lastCloseLocktime;
		delete serialized.lastCloseCloserScript;
		delete serialized.lastCloseCloseeScript;
		delete serialized.lastCloseSentVariants;
		const legacy = deserializeChannelState(serialized);
		expect(legacy.simpleClose).to.equal(null);
		expect(legacy.lastLocalClosingComplete).to.equal(null);
		expect(legacy.awaitingClosingSig).to.equal(false);
	});
});
