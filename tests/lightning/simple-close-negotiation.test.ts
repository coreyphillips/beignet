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
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
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
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	serializeChannelState,
	deserializeChannelState,
	serializeChainMonitorState,
	deserializeChainMonitorState
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

/**
 * A CLOSED channel whose recorded mutual close pays a 1-sat fee: the shape the
 * relay-floor rescue admits, because no mempool will relay it.
 */
function closedWithStarvedCoopClose(
	seedA: number,
	seedB: number
): { h: IHarness; starved: bitcoin.Transaction; destScript: Buffer } {
	const h = openChannelHarness(seedA, seedB, 400_000_000n);
	h.alice.on('error', () => {});
	expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(true);
	pump(h.aliceOut, h.bob, h.aPub);
	pump(h.bobOut, h.alice, h.bPub);
	pump(h.aliceOut, h.bob, h.aPub);
	pump(h.bobOut, h.alice, h.bPub);
	expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
	const state = h.aliceChannel.getFullState();
	h.aliceChannel.setBlockHeight(800_000);

	const starved = bitcoin.Transaction.fromHex(state.lastCooperativeCloseTxHex!);
	const outputTotal = starved.outs.reduce((sum, o) => sum + o.value, 0);
	starved.outs[0].value += Number(state.fundingSatoshis) - outputTotal - 1;
	h.aliceChannel.recordCooperativeCloseTx(starved.toHex());
	return {
		h,
		starved,
		destScript: Buffer.from('0014' + 'dd'.repeat(20), 'hex')
	};
}

/** Round-trip alice's monitor through storage, as a restart does. */
function restartMonitor(h: IHarness, destScript: Buffer): ChainMonitor {
	const live = h.alice.getMonitor(h.channelId)!;
	const restored = ChainMonitor.restore(
		deserializeChainMonitorState(
			serializeChainMonitorState(live.getFullState())
		),
		h.aliceChannel.getFullState(),
		destScript,
		10,
		h.alice['config'].localFundingPrivkey,
		h.alice['config'].localFundingPrivkey
	);
	h.alice.restoreMonitor(h.channelId.toString('hex'), restored);
	return restored;
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

		it('far-future or timestamp-space locktime is rejected before signing', function () {
			const h = negotiatingHarness(23, 24);
			h.bobChannel.setBlockHeight(800_000);
			const errors: string[] = [];
			h.bob.on('error', (_id, msg: string) => errors.push(msg));

			// The issue #555 attack: a consensus-enforced locktime ~9000 years
			// out, over which the peer's signature would verify just fine.
			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, { locktime: 499_999_999 })
			);
			expect(
				errors.some((e) => /locktime 499999999 is beyond our chain tip/.test(e))
			).to.equal(true);

			// Timestamp-space values are refused outright.
			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, { locktime: 500_000_000 })
			);
			expect(
				errors.some((e) => /locktime 500000000 is not a block height/.test(e))
			).to.equal(true);

			expect(h.bobChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
			expect(h.bobTxs.length).to.equal(0);
			expect(h.bobOut.some((m) => m.type === MessageType.CLOSING_SIG)).to.equal(
				false
			);
		});

		it('locktime within the tip tolerance is admitted; one block past it is not', function () {
			const h = negotiatingHarness(25, 26);
			h.bobChannel.setBlockHeight(800_000);
			const errors: string[] = [];
			h.bob.on('error', (_id, msg: string) => errors.push(msg));

			// tip + tolerance: the locktime gate admits it, so the garbage
			// signature is what gets refused.
			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, { locktime: 800_006 })
			);
			expect(errors.some((e) => /locktime/.test(e))).to.equal(false);
			expect(errors.some((e) => /signature failed to verify/.test(e))).to.equal(
				true
			);

			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, { locktime: 800_007 })
			);
			expect(
				errors.some((e) =>
					/locktime 800007 is beyond our chain tip 800000/.test(e)
				)
			).to.equal(true);
			expect(h.bobTxs.length).to.equal(0);
		});

		it('nonzero locktime with no chain tip is refused', function () {
			const h = negotiatingHarness(27, 28);
			const errors: string[] = [];
			h.bob.on('error', (_id, msg: string) => errors.push(msg));

			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, { locktime: 800_000 })
			);
			expect(
				errors.some((e) => /no chain tip to validate locktime/.test(e))
			).to.equal(true);
			expect(h.bobChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);
			expect(h.bobTxs.length).to.equal(0);
		});

		it('force close exits a negotiation wedged on a rejected locktime', function () {
			const h = negotiatingHarness(31, 32);
			h.bobChannel.setBlockHeight(800_000);
			const errors: string[] = [];
			h.bob.on('error', (_id, msg: string) => errors.push(msg));

			h.bob.handleMessage(
				h.aPub,
				MessageType.CLOSING_COMPLETE,
				craftedClosingComplete(h, { locktime: 499_999_999 })
			);
			expect(errors.some((e) => /beyond our chain tip/.test(e))).to.equal(true);
			expect(h.bobChannel.getState()).to.equal(
				ChannelState.NEGOTIATING_CLOSING
			);

			// The refusal must not strand the channel: the peer may never send
			// an acceptable locktime, so the unilateral exit has to be available
			// from NEGOTIATING_CLOSING while the peer is still connected.
			const destScript = Buffer.from('0014' + 'ee'.repeat(20), 'hex');
			const result = h.bob.forceClose(h.channelId, destScript, 10);
			expect(result.ok).to.equal(true);
			const broadcast = result.actions.find(
				(a) => a.type === ChannelActionType.BROADCAST_TX
			) as { tx: Buffer } | undefined;
			expect(broadcast).to.exist;
			const bobState = h.bobChannel.getFullState();
			const commitment = bitcoin.Transaction.fromBuffer(broadcast!.tx);
			expect(
				commitment.ins[0].hash.equals(bobState.fundingTxid!),
				'commitment spends the funding outpoint'
			).to.equal(true);
			expect(h.bobChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);
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

	it('force close recovers a CLOSED channel whose recorded mutual close cannot be broadcast', function () {
		const h = openChannelHarness(29, 30, 400_000_000n);
		h.alice.on('error', () => {});
		expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
			true
		);
		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		const state = h.aliceChannel.getFullState();
		expect(state.lastCooperativeCloseTxHex).to.be.a('string');

		// A broadcastable close (locktime 0) keeps CLOSED terminal.
		const destScript = Buffer.from('0014' + 'dd'.repeat(20), 'hex');
		h.aliceChannel.setBlockHeight(800_000);
		const refused = h.alice.forceClose(h.channelId, destScript, 10);
		expect(refused.ok).to.equal(false);
		expect(refused.error).to.match(/wrong state/);

		// A victim row persisted before the locktime bound existed: the
		// recorded close carries a far-future locktime, so no broadcast of it
		// can ever be accepted. Force close must offer the unilateral exit.
		const mangled = bitcoin.Transaction.fromHex(
			state.lastCooperativeCloseTxHex!
		);
		mangled.locktime = 499_999_999;
		h.aliceChannel.recordCooperativeCloseTx(mangled.toHex());

		const result = h.alice.forceClose(h.channelId, destScript, 10);
		expect(result.ok).to.equal(true);
		const broadcast = result.actions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { tx: Buffer } | undefined;
		expect(broadcast).to.exist;
		const commitment = bitcoin.Transaction.fromBuffer(broadcast!.tx);
		expect(
			commitment.ins[0].hash.equals(state.fundingTxid!),
			'commitment spends the funding outpoint'
		).to.equal(true);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);
	});

	it('force close recovers a CLOSED channel whose recorded mutual close pays under the relay floor', function () {
		// Issue #579: the sibling dead end. A close signed below the default
		// 1 sat/vB relay floor is rejected by every mempool, and only the peer
		// (whose output pays the fee) could replace it, so CLOSED must not be
		// terminal for it either.
		const h = openChannelHarness(31, 32, 400_000_000n);
		h.alice.on('error', () => {});
		expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
			true
		);
		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		const state = h.aliceChannel.getFullState();
		h.aliceChannel.setBlockHeight(800_000);

		// The negotiated close pays a relayable fee, so CLOSED stands.
		const destScript = Buffer.from('0014' + 'dd'.repeat(20), 'hex');
		const refused = h.alice.forceClose(h.channelId, destScript, 10);
		expect(refused.ok).to.equal(false);
		expect(refused.error).to.match(/wrong state/);

		// Hand the fee back to the outputs, leaving 1 sat of fee on a ~169
		// vbyte tx: the shape a peer-chosen sub-relay fee records.
		const starved = bitcoin.Transaction.fromHex(
			state.lastCooperativeCloseTxHex!
		);
		const outputTotal = starved.outs.reduce((sum, o) => sum + o.value, 0);
		starved.outs[0].value += Number(state.fundingSatoshis) - outputTotal - 1;
		h.aliceChannel.recordCooperativeCloseTx(starved.toHex());

		const result = h.alice.forceClose(h.channelId, destScript, 10);
		expect(result.ok).to.equal(true);
		const broadcast = result.actions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { tx: Buffer } | undefined;
		expect(broadcast).to.exist;
		const commitment = bitcoin.Transaction.fromBuffer(broadcast!.tx);
		expect(
			commitment.ins[0].hash.equals(state.fundingTxid!),
			'commitment spends the funding outpoint'
		).to.equal(true);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);
	});

	it('force close refuses a CLOSED channel whose sub-relay-fee close already confirmed', function () {
		// Issue #622: the relay-floor arm judges the recorded tx alone, and a
		// close under the floor is the one dead end a miner can still include
		// out of band. Confirmed, it is not a dead end at all: it is the
		// transaction that settled the channel.
		const { h, starved, destScript } = closedWithStarvedCoopClose(33, 34);

		// A miner included it anyway: the funding spend is confirmed at 800000.
		h.alice.handleFundingSpent(h.channelId, starved, 800_000, destScript);
		const monitor = h.alice.getMonitor(h.channelId)!;
		expect(monitor.isCommitmentConfirmed()).to.equal(true);
		expect(monitor.getFullState().commitmentBroadcast?.txid).to.equal(
			starved.getId()
		);

		const broadcastsBefore = h.aliceTxs.length;
		const refused = h.alice.forceClose(h.channelId, destScript, 10);
		expect(refused.ok).to.equal(false);
		expect(refused.error).to.match(/already confirmed on chain/);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(h.aliceTxs.length, 'no commitment broadcast').to.equal(
			broadcastsBefore
		);
		// The confirmed close's record survives, monitor object and all.
		expect(h.alice.getMonitor(h.channelId)).to.equal(monitor);
		expect(monitor.isCommitmentConfirmed()).to.equal(true);
		expect(monitor.getFullState().commitmentBroadcast?.txid).to.equal(
			starved.getId()
		);
	});

	it('force close refuses while a restored close is still unproved', function () {
		// Restore drops a cooperative close's persisted height (the
		// fresh-evidence rule) until the re-armed funding watch reports, so
		// isCommitmentConfirmed() answers false for a close that IS on chain.
		// Reading the rescue's gate off that alone re-admitted the whole
		// defect for as long as the window lasts.
		const { h, starved, destScript } = closedWithStarvedCoopClose(37, 38);
		h.alice.handleFundingSpent(h.channelId, starved, 800_000, destScript);
		expect(h.alice.getMonitor(h.channelId)!.isCommitmentConfirmed()).to.equal(
			true
		);

		const restored = restartMonitor(h, destScript);
		expect(restored.isCommitmentConfirmed()).to.equal(false);
		expect(restored.isCommitmentReverifyPending()).to.equal(true);

		// Startup persists the reset height before the funding watch reports.
		h.alice.handleNewBlock(800_010);
		const restoredAgain = restartMonitor(h, destScript);
		expect(
			restoredAgain.getFullState().commitmentBroadcast?.blockHeight
		).to.equal(0);
		expect(restoredAgain.isCommitmentConfirmed()).to.equal(false);
		expect(restoredAgain.isCommitmentReverifyPending()).to.equal(true);

		const broadcastsBefore = h.aliceTxs.length;
		const refused = h.alice.forceClose(h.channelId, destScript, 10);
		expect(refused.ok).to.equal(false);
		expect(refused.error).to.match(/may already be confirmed/);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(h.aliceTxs.length, 'no commitment broadcast').to.equal(
			broadcastsBefore
		);
		expect(h.alice.getMonitor(h.channelId)).to.equal(restoredAgain);
		expect(restoredAgain.getFullState().commitmentBroadcast?.txid).to.equal(
			starved.getId()
		);

		// The watch re-reports the spend: the same refusal, now on proof.
		h.alice.handleFundingSpent(h.channelId, starved, 800_000, destScript);
		expect(restoredAgain.isCommitmentReverifyPending()).to.equal(false);
		expect(restoredAgain.isCommitmentConfirmed()).to.equal(true);
		expect(h.alice.forceClose(h.channelId, destScript, 10).error).to.match(
			/already confirmed on chain/
		);
	});

	it('an absent-spend report reopens the rescue for a restored close', function () {
		// The window has to CLOSE on evidence either way, or a close that was
		// really reorged out while we were offline would leave the channel with
		// no exit at all - the dead end the rescue exists for.
		const { h, starved, destScript } = closedWithStarvedCoopClose(39, 40);
		h.alice.handleFundingSpent(h.channelId, starved, 800_000, destScript);
		const restored = restartMonitor(h, destScript);
		expect(restored.isCommitmentReverifyPending()).to.equal(true);

		const state = h.aliceChannel.getFullState();
		const retracted = h.alice.handleFundingSpendAbsent(h.channelId, {
			txid: Buffer.from(state.fundingTxid!).reverse().toString('hex'),
			outputIndex: state.fundingOutputIndex!
		});
		// Nothing to demote: the restore already zeroed the recorded height.
		expect(retracted).to.equal(false);
		expect(restored.isCommitmentReverifyPending()).to.equal(false);

		const rescued = h.alice.forceClose(h.channelId, destScript, 10);
		expect(rescued.ok).to.equal(true);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.FORCE_CLOSED);
	});

	it("a sibling outpoint's absence leaves a restored close unproved", function () {
		// A pre-splice leg is re-armed ahead of the canonical funding watch and
		// scans a different outpoint. Its silence is evidence about that outpoint
		// alone, so it may stop the depth clock but must not answer the rescue's
		// question about this close.
		const { h, starved, destScript } = closedWithStarvedCoopClose(41, 42);
		h.alice.handleFundingSpent(h.channelId, starved, 800_000, destScript);
		const restored = restartMonitor(h, destScript);
		expect(restored.isCommitmentReverifyPending()).to.equal(true);
		expect(
			restored.getFullState().commitmentBroadcast?.spentOutpoint,
			'a record written without an outpoint'
		).to.equal(undefined);

		const retracted = h.alice.handleFundingSpendAbsent(h.channelId, {
			txid: 'ee'.repeat(32),
			outputIndex: 0,
			expectedSpendTxid: 'ff'.repeat(32)
		});
		expect(retracted).to.equal(false);
		expect(restored.isCommitmentReverifyPending()).to.equal(true);

		const broadcastsBefore = h.aliceTxs.length;
		const refused = h.alice.forceClose(h.channelId, destScript, 10);
		expect(refused.ok).to.equal(false);
		expect(refused.error).to.match(/may already be confirmed/);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		expect(h.aliceTxs.length, 'no commitment broadcast').to.equal(
			broadcastsBefore
		);
		expect(h.alice.getMonitor(h.channelId)).to.equal(restored);
	});

	it('force close keeps a monitor whose funding spend is already confirmed', function () {
		// The other half of issue #622: whatever admitted the plan, replacing
		// the monitor throws away the tracked outputs, the classification and
		// the irrevocable-depth clock of a spend that is already on chain.
		const h = openChannelHarness(35, 36, 400_000_000n);
		h.alice.on('error', () => {});
		expect(h.alice.initiateShutdown(h.channelId, ALICE_SCRIPT).ok).to.equal(
			true
		);
		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		pump(h.aliceOut, h.bob, h.aPub);
		pump(h.bobOut, h.alice, h.bPub);
		expect(h.aliceChannel.getState()).to.equal(ChannelState.CLOSED);
		const state = h.aliceChannel.getFullState();
		h.aliceChannel.setBlockHeight(800_000);

		// Reach FORCE_CLOSED through the locktime rescue, then confirm the
		// commitment it broadcast.
		const mangled = bitcoin.Transaction.fromHex(
			state.lastCooperativeCloseTxHex!
		);
		mangled.locktime = 499_999_999;
		h.aliceChannel.recordCooperativeCloseTx(mangled.toHex());
		const destScript = Buffer.from('0014' + 'dd'.repeat(20), 'hex');
		const closed = h.alice.forceClose(h.channelId, destScript, 10);
		expect(closed.ok).to.equal(true);
		const broadcast = closed.actions.find(
			(a) => a.type === ChannelActionType.BROADCAST_TX
		) as { tx: Buffer } | undefined;
		const commitment = bitcoin.Transaction.fromBuffer(broadcast!.tx);
		h.alice.handleFundingSpent(h.channelId, commitment, 800_001, destScript);
		const monitor = h.alice.getMonitor(h.channelId)!;
		expect(monitor.isCommitmentConfirmed()).to.equal(true);
		const trackedOutputs = monitor.getTrackedOutputs().length;
		expect(trackedOutputs).to.be.greaterThan(0);

		// FORCE_CLOSED re-admits the plan (the rebroadcast path), so the
		// refusal above cannot be what protects the monitor here.
		const again = h.alice.forceClose(h.channelId, destScript, 10);
		expect(again.ok).to.equal(true);
		expect(h.alice.getMonitor(h.channelId)).to.equal(monitor);
		expect(monitor.isCommitmentConfirmed()).to.equal(true);
		expect(monitor.getFullState().commitmentBroadcast?.txid).to.equal(
			commitment.getId()
		);
		expect(monitor.getTrackedOutputs().length).to.equal(trackedOutputs);
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
