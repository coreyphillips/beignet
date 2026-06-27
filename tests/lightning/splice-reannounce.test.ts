/**
 * Post-splice channel re-announcement (BOLT 7).
 *
 * Live mainnet bug: after a splice, the funding outpoint (and therefore the
 * SCID) changes, but the announcement state was never reset. When CLN re-sent
 * announcement_signatures for the NEW scid, beignet combined them with its
 * stale SCID and stale local signatures into a channel_announcement the
 * network rejects ("Bad node_signature_1").
 *
 * Covers:
 * 1. handleAnnouncementSignatures adopts a changed SCID and discards stale
 *    local sigs instead of building a mixed (invalid) announcement.
 * 2. Re-signing afterwards produces an announcement where ALL FOUR signatures
 *    verify over its own hash.
 * 3. completeSplice() resets announcement state.
 * 4. ChannelManager emits announcement:needs-signing with the NEW scid.
 * 5. LightningNode verifies the claimed SCID against the funding tx position
 *    before signing.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { encodeAnnouncementSignaturesMessage } from '../../src/lightning/gossip/messages';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { Network } from '../../src/lightning/invoice/types';

// ─────────────── Helpers ───────────────

function sha256d(data: Buffer): Buffer {
	return crypto
		.createHash('sha256')
		.update(crypto.createHash('sha256').update(data).digest())
		.digest();
}

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		privkeys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(privkeys[0]),
			revocationBasepoint: getPublicKey(privkeys[1]),
			paymentBasepoint: getPublicKey(privkeys[2]),
			delayedPaymentBasepoint: getPublicKey(privkeys[3]),
			htlcBasepoint: getPublicKey(privkeys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		privkeys
	};
}

function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a) => a.type === 'SEND_MESSAGE' && a.messageType === msgType
	);
}

function setupNormalChannels(): {
	opener: Channel;
	openerPrivkeys: Buffer[];
	acceptorPrivkeys: Buffer[];
	openerBasepoints: IChannelBasepoints;
	openerCommitmentSeed: Buffer;
} {
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update('reann-opener')
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update('reann-acceptor')
		.digest();
	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(Buffer.alloc(32, 0x61));
	const { basepoints: acceptorBasepoints, privkeys: acceptorPrivkeys } =
		makeBasepoints(Buffer.alloc(32, 0x62));

	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xee),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBasepoints,
			localPerCommitmentSeed: openerCommitmentSeed
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: Buffer.alloc(32, 0xee),
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBasepoints,
			localPerCommitmentSeed: acceptorCommitmentSeed,
			remoteBasepoints: openerBasepoints,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);

	const openActions = opener.initiateOpen();
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(
			findSendAction(openActions, MessageType.OPEN_CHANNEL).payload
		)
	);
	opener.handleAcceptChannel(
		decodeAcceptChannelMessage(
			findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL).payload
		)
	);
	const fcActions = opener.createFundingCreated(
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	);
	const fsActions = acceptor.handleFundingCreated(
		decodeFundingCreatedMessage(
			findSendAction(fcActions, MessageType.FUNDING_CREATED).payload
		),
		crypto.randomBytes(64)
	);
	opener.handleFundingSigned(
		decodeFundingSignedMessage(
			findSendAction(fsActions, MessageType.FUNDING_SIGNED).payload
		)
	);
	const orActions = opener.fundingConfirmed();
	acceptor.handleChannelReady(
		decodeChannelReadyMessage(
			findSendAction(orActions, MessageType.CHANNEL_READY).payload
		)
	);
	const arActions = acceptor.fundingConfirmed();
	opener.handleChannelReady(
		decodeChannelReadyMessage(
			findSendAction(arActions, MessageType.CHANNEL_READY).payload
		)
	);
	expect(opener.getState()).to.equal(ChannelState.NORMAL);

	return {
		opener,
		openerPrivkeys,
		acceptorPrivkeys,
		openerBasepoints,
		openerCommitmentSeed
	};
}

/** Replicate Channel.buildAnnouncementData for a given side's view. */
function buildAnnData(
	scid: Buffer,
	localNodeId: Buffer,
	remoteNodeId: Buffer,
	localFundingPub: Buffer,
	remoteFundingPub: Buffer
): Buffer {
	const isNode1 = Buffer.compare(localNodeId, remoteNodeId) < 0;
	return Buffer.concat([
		Buffer.alloc(2),
		BITCOIN_CHAIN_HASH,
		scid,
		isNode1 ? localNodeId : remoteNodeId,
		isNode1 ? remoteNodeId : localNodeId,
		isNode1 ? localFundingPub : remoteFundingPub,
		isNode1 ? remoteFundingPub : localFundingPub
	]);
}

function makeSigner(
	nodePriv: Buffer,
	fundingPriv: Buffer
): (data: Buffer) => { nodeSig: Buffer; bitcoinSig: Buffer } {
	return (data: Buffer) => {
		const hash = sha256d(data);
		return {
			nodeSig: Buffer.from(ecc.sign(hash, nodePriv)),
			bitcoinSig: Buffer.from(ecc.sign(hash, fundingPriv))
		};
	};
}

/** Parse an encoded channel_announcement payload (no type prefix) and verify all 4 sigs. */
function verifyFullAnnouncement(payload: Buffer): {
	scid: Buffer;
	allValid: boolean;
} {
	const hash = sha256d(payload.subarray(256));
	let o = 0;
	const sigs: Buffer[] = [];
	for (let i = 0; i < 4; i++) {
		sigs.push(payload.subarray(o, o + 64));
		o += 64;
	}
	const flen = payload.readUInt16BE(o);
	o += 2 + flen;
	o += 32; // chain hash
	const scid = payload.subarray(o, o + 8);
	o += 8;
	const keys: Buffer[] = [];
	for (let i = 0; i < 4; i++) {
		keys.push(payload.subarray(o, o + 33));
		o += 33;
	}
	// node_sig_1↔node_id_1, node_sig_2↔node_id_2, btc_sig_1↔btc_key_1, btc_sig_2↔btc_key_2
	const pairs: Array<[Buffer, Buffer]> = [
		[sigs[0], keys[0]],
		[sigs[1], keys[1]],
		[sigs[2], keys[2]],
		[sigs[3], keys[3]]
	];
	const allValid = pairs.every(([sig, key]) => {
		try {
			return ecc.verify(hash, key, sig);
		} catch {
			return false;
		}
	});
	return { scid: Buffer.from(scid), allValid };
}

const SCID_A = encodeShortChannelId({
	block: 953275,
	txIndex: 847,
	outputIndex: 0
});
const SCID_B = encodeShortChannelId({
	block: 953375,
	txIndex: 1174,
	outputIndex: 0
});

// Node identity keys (separate from channel basepoints, like real nodes)
const localNodePriv = crypto
	.createHash('sha256')
	.update('reann-local-node')
	.digest();
const remoteNodePriv = crypto
	.createHash('sha256')
	.update('reann-remote-node')
	.digest();
const localNodeId = getPublicKey(localNodePriv);
const remoteNodeId = getPublicKey(remoteNodePriv);

describe('Post-splice channel re-announcement', function () {
	function announceForScidA(
		opener: Channel,
		openerPrivkeys: Buffer[],
		acceptorPrivkeys: Buffer[]
	): void {
		// Our side signs + sends announcement_signatures for SCID A
		const actions = opener.handleAnnouncementDepthReached(
			953275,
			847,
			localNodeId,
			remoteNodeId,
			makeSigner(localNodePriv, openerPrivkeys[0])
		);
		expect(findSendAction(actions, MessageType.ANNOUNCEMENT_SIGNATURES)).to
			.exist;

		// Peer signs SCID A and sends announcement_signatures
		const remoteData = buildAnnData(
			SCID_A,
			remoteNodeId,
			localNodeId,
			getPublicKey(acceptorPrivkeys[0]),
			getPublicKey(openerPrivkeys[0])
		);
		const remoteHash = sha256d(remoteData);
		const st = opener.getFullState();
		const readyActions = opener.handleAnnouncementSignatures(
			{
				channelId: opener.getChannelId()!,
				shortChannelId: SCID_A,
				nodeSignature: Buffer.from(ecc.sign(remoteHash, remoteNodePriv)),
				bitcoinSignature: Buffer.from(ecc.sign(remoteHash, acceptorPrivkeys[0]))
			},
			localNodeId,
			remoteNodeId,
			st.localAnnouncementNodeSig ?? undefined,
			st.localAnnouncementBitcoinSig ?? undefined
		);
		const ready = readyActions.find(
			(a: any) => a.type === ChannelActionType.ANNOUNCEMENT_READY
		) as any;
		expect(ready, 'announcement built for SCID A').to.exist;
		const { scid, allValid } = verifyFullAnnouncement(
			ready.channelAnnouncement
		);
		expect(scid.equals(SCID_A)).to.be.true;
		expect(allValid, 'baseline announcement valid').to.be.true;
	}

	it('adopts the new SCID and discards stale local sigs on a post-splice re-announce', function () {
		const { opener, openerPrivkeys, acceptorPrivkeys } = setupNormalChannels();
		announceForScidA(opener, openerPrivkeys, acceptorPrivkeys);

		// Peer re-announces with SCID B (post-splice). Their sigs are over SCID B.
		const remoteDataB = buildAnnData(
			SCID_B,
			remoteNodeId,
			localNodeId,
			getPublicKey(acceptorPrivkeys[0]),
			getPublicKey(openerPrivkeys[0])
		);
		const remoteHashB = sha256d(remoteDataB);
		const st = opener.getFullState();
		const actions = opener.handleAnnouncementSignatures(
			{
				channelId: opener.getChannelId()!,
				shortChannelId: SCID_B,
				nodeSignature: Buffer.from(ecc.sign(remoteHashB, remoteNodePriv)),
				bitcoinSignature: Buffer.from(
					ecc.sign(remoteHashB, acceptorPrivkeys[0])
				)
			},
			localNodeId,
			remoteNodeId,
			st.localAnnouncementNodeSig ?? undefined,
			st.localAnnouncementBitcoinSig ?? undefined
		);

		// MUST NOT build a mixed announcement (old SCID + new remote sigs)
		expect(
			actions.find((a: any) => a.type === ChannelActionType.ANNOUNCEMENT_READY)
		).to.be.undefined;
		expect(actions.find((a: any) => a.type === ChannelActionType.PERSIST_STATE))
			.to.exist;

		const updated = opener.getFullState();
		expect(updated.shortChannelId!.equals(SCID_B), 'adopted new SCID').to.be
			.true;
		expect(updated.announcementSigsSent, 'stale local sigs invalidated').to.be
			.false;
		expect(updated.localAnnouncementNodeSig).to.be.null;
		expect(updated.localAnnouncementBitcoinSig).to.be.null;
		expect(updated.announcementSigsReceived).to.be.true;
	});

	it('re-signing after the SCID change produces a fully valid announcement', function () {
		const { opener, openerPrivkeys, acceptorPrivkeys } = setupNormalChannels();
		announceForScidA(opener, openerPrivkeys, acceptorPrivkeys);

		// Peer re-announces with SCID B
		const remoteDataB = buildAnnData(
			SCID_B,
			remoteNodeId,
			localNodeId,
			getPublicKey(acceptorPrivkeys[0]),
			getPublicKey(openerPrivkeys[0])
		);
		const remoteHashB = sha256d(remoteDataB);
		let st = opener.getFullState();
		opener.handleAnnouncementSignatures(
			{
				channelId: opener.getChannelId()!,
				shortChannelId: SCID_B,
				nodeSignature: Buffer.from(ecc.sign(remoteHashB, remoteNodePriv)),
				bitcoinSignature: Buffer.from(
					ecc.sign(remoteHashB, acceptorPrivkeys[0])
				)
			},
			localNodeId,
			remoteNodeId,
			st.localAnnouncementNodeSig ?? undefined,
			st.localAnnouncementBitcoinSig ?? undefined
		);

		// needs-signing path: re-sign for the new funding position
		const actions = opener.handleAnnouncementDepthReached(
			953375,
			1174,
			localNodeId,
			remoteNodeId,
			makeSigner(localNodePriv, openerPrivkeys[0])
		);
		expect(
			findSendAction(actions, MessageType.ANNOUNCEMENT_SIGNATURES),
			're-sent our sigs'
		).to.exist;
		const ready = actions.find(
			(a: any) => a.type === ChannelActionType.ANNOUNCEMENT_READY
		) as any;
		expect(ready, 'announcement rebuilt').to.exist;

		const { scid, allValid } = verifyFullAnnouncement(
			ready.channelAnnouncement
		);
		expect(scid.equals(SCID_B), 'announcement carries the NEW scid').to.be.true;
		expect(allValid, 'ALL FOUR signatures verify (the live-bug regression)').to
			.be.true;

		st = opener.getFullState();
		expect(st.fundingConfirmationHeight).to.equal(953375);
		expect(st.fundingTxIndex).to.equal(1174);
	});

	it('completeSplice() resets announcement state for the new funding generation', function () {
		const { opener } = setupNormalChannels();
		const anyOpener = opener as any;

		// Simulate an announced channel mid-splice
		const st = opener.getFullState();
		st.shortChannelId = Buffer.from(SCID_A);
		st.announcementSigsSent = true;
		st.announcementSigsReceived = true;
		st.localAnnouncementNodeSig = crypto.randomBytes(64);
		st.localAnnouncementBitcoinSig = crypto.randomBytes(64);
		st.remoteAnnouncementNodeSig = crypto.randomBytes(64);
		st.remoteAnnouncementBitcoinSig = crypto.randomBytes(64);
		st.fundingConfirmationHeight = 953275;
		st.fundingTxIndex = 847;
		anyOpener._state.state = ChannelState.SPLICING;
		anyOpener._spliceSession = {
			getSpliceTxid: () => crypto.randomBytes(32),
			getSpliceFundingOutputIndex: () => 0,
			getNetCapacityChange: () => 0n,
			getLocalRelativeSatoshis: () => 0n,
			getRemoteRelativeSatoshis: () => 0n,
			isInitiator: () => true
		};
		anyOpener._spliceTx = null;

		anyOpener.completeSplice();

		const updated = opener.getFullState();
		expect(updated.state).to.equal(ChannelState.NORMAL);
		expect(updated.announcementSigsSent).to.be.false;
		expect(updated.announcementSigsReceived).to.be.false;
		expect(updated.localAnnouncementNodeSig).to.be.null;
		expect(updated.localAnnouncementBitcoinSig).to.be.null;
		expect(updated.remoteAnnouncementNodeSig).to.be.null;
		expect(updated.remoteAnnouncementBitcoinSig).to.be.null;
		expect(updated.fundingConfirmationHeight).to.equal(0);
		expect(updated.fundingTxIndex).to.equal(0);
		// Old SCID kept for forwarding continuity until the new one is computed
		expect(updated.shortChannelId!.equals(SCID_A)).to.be.true;
	});

	it('ChannelManager emits announcement:needs-signing with the NEW scid', function () {
		const {
			opener,
			openerPrivkeys,
			acceptorPrivkeys,
			openerBasepoints,
			openerCommitmentSeed
		} = setupNormalChannels();
		announceForScidA(opener, openerPrivkeys, acceptorPrivkeys);

		const config: IChannelManagerConfig = {
			localBasepoints: openerBasepoints,
			localPerCommitmentSeed: openerCommitmentSeed,
			localFundingPrivkey: openerPrivkeys[0],
			nodePrivateKey: localNodePriv
		};
		const manager = new ChannelManager(config);
		const channelId = opener.getChannelId()!;
		(manager as any).channels.set(channelId.toString('hex'), opener);
		(manager as any).channelPeers.set(
			channelId.toString('hex'),
			remoteNodeId.toString('hex')
		);

		const emitted: Buffer[] = [];
		manager.on('announcement:needs-signing', (_cid: Buffer, scid: Buffer) =>
			emitted.push(scid)
		);

		const remoteDataB = buildAnnData(
			SCID_B,
			remoteNodeId,
			localNodeId,
			getPublicKey(acceptorPrivkeys[0]),
			getPublicKey(openerPrivkeys[0])
		);
		const remoteHashB = sha256d(remoteDataB);
		const payload = encodeAnnouncementSignaturesMessage({
			channelId,
			shortChannelId: SCID_B,
			nodeSignature: Buffer.from(ecc.sign(remoteHashB, remoteNodePriv)),
			bitcoinSignature: Buffer.from(ecc.sign(remoteHashB, acceptorPrivkeys[0]))
		});
		manager.handleMessage(
			remoteNodeId.toString('hex'),
			MessageType.ANNOUNCEMENT_SIGNATURES,
			payload
		);

		expect(emitted.length).to.equal(1);
		expect(emitted[0].equals(SCID_B), 'needs-signing fired with the NEW scid')
			.to.be.true;
	});

	describe('Proactive re-announcement after splice completion', function () {
		it('sendSpliceLocked emits SPLICE_COMPLETE when the splice finishes', function () {
			const { opener } = setupNormalChannels();
			const anyOpener = opener as any;
			anyOpener._state.state = ChannelState.SPLICING;
			anyOpener._state.spliceInFlight = null;
			anyOpener._spliceSession = {
				hasSentSpliceLocked: () => false,
				sendSpliceLocked: () => ({
					ok: true,
					message: {
						channelId: opener.getChannelId()!,
						fundingTxid: crypto.randomBytes(32)
					}
				}),
				handleSpliceLocked: () => ({ ok: true }),
				isComplete: () => true,
				getSpliceTxid: () => crypto.randomBytes(32),
				getSpliceFundingOutputIndex: () => 0,
				getNetCapacityChange: () => 0n,
				getLocalRelativeSatoshis: () => 0n,
				getRemoteRelativeSatoshis: () => 0n,
				isInitiator: () => true
			};
			anyOpener._spliceTx = null;

			const actions = opener.sendSpliceLocked();
			expect(
				actions.find((a: any) => a.type === ChannelActionType.SPLICE_COMPLETE),
				'SPLICE_COMPLETE action emitted'
			).to.exist;
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
		});

		it('ChannelManager surfaces SPLICE_COMPLETE as splice:complete', function () {
			const { opener, openerPrivkeys, openerBasepoints, openerCommitmentSeed } =
				setupNormalChannels();
			const manager = new ChannelManager({
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			});
			const channelId = opener.getChannelId()!;
			(manager as any).channels.set(channelId.toString('hex'), opener);
			(manager as any).channelPeers.set(
				channelId.toString('hex'),
				remoteNodeId.toString('hex')
			);

			const emitted: Buffer[] = [];
			manager.on('splice:complete', (cid: Buffer) => emitted.push(cid));
			(manager as any).processActions(remoteNodeId.toString('hex'), opener, [
				{ type: ChannelActionType.SPLICE_COMPLETE }
			]);
			expect(emitted.length).to.equal(1);
			expect(emitted[0].equals(channelId)).to.be.true;
		});

		it('rearmAnnouncementTracking fires announcement:depth immediately when already 6 deep', async function () {
			const { ChainWatcher } = await import(
				'../../src/lightning/chain/chain-watcher'
			);
			const backend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => '',
				getTransactionMerkleProof: async (_t: string, h: number) => ({
					blockHeight: h,
					txIndex: 1174
				})
			};
			const fakeManager = {
				handleNewBlock: () => [],
				handleFundingConfirmed: () => {},
				on: () => {}
			};
			const watcher = new ChainWatcher({
				backend,
				channelManager: fakeManager as any
			});
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');

			// Simulate the splice funding watch whose one-shot burnt mid-splice
			(watcher as any).currentBlockHeight = 953399;
			(watcher as any).watchedFundings.set(`${txid}:0`, {
				channelId,
				txid,
				outputIndex: 0,
				minimumDepth: 3,
				scriptHash: 'ab'.repeat(32),
				confirmed: true,
				confirmationHeight: 953375,
				announcementTriggered: true
			});

			const fired: Array<{ height: number; txIndex: number }> = [];
			watcher.on(
				'announcement:depth',
				(_cid: Buffer, height: number, txIndex: number) => {
					fired.push({ height, txIndex });
				}
			);

			watcher.rearmAnnouncementTracking(channelId, txid);
			await new Promise((r) => setImmediate(r));
			expect(fired).to.deep.equal([{ height: 953375, txIndex: 1174 }]);

			// Wrong txid: no re-arm, no fire
			watcher.rearmAnnouncementTracking(
				channelId,
				crypto.randomBytes(32).toString('hex')
			);
			await new Promise((r) => setImmediate(r));
			expect(fired.length).to.equal(1);
		});

		it('rearmAnnouncementTracking only resets the flag when not yet 6 deep', async function () {
			const { ChainWatcher } = await import(
				'../../src/lightning/chain/chain-watcher'
			);
			const backend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => ''
			};
			const fakeManager = {
				handleNewBlock: () => [],
				handleFundingConfirmed: () => {},
				on: () => {}
			};
			const watcher = new ChainWatcher({
				backend,
				channelManager: fakeManager as any
			});
			const channelId = crypto.randomBytes(32);
			const txid = crypto.randomBytes(32).toString('hex');

			(watcher as any).currentBlockHeight = 953377; // only 3 confs
			const entry = {
				channelId,
				txid,
				outputIndex: 0,
				minimumDepth: 3,
				scriptHash: 'cd'.repeat(32),
				confirmed: true,
				confirmationHeight: 953375,
				announcementTriggered: true
			};
			(watcher as any).watchedFundings.set(`${txid}:0`, entry);

			const fired: number[] = [];
			watcher.on('announcement:depth', (_c: Buffer, h: number) =>
				fired.push(h)
			);
			watcher.rearmAnnouncementTracking(channelId, txid);
			await new Promise((r) => setImmediate(r));

			expect(fired.length).to.equal(0);
			expect(entry.announcementTriggered, 'flag reset for next-block check').to
				.be.false;
		});

		it('LightningNode re-arms the new funding watch on splice:complete', function () {
			const backend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => ''
			};
			const seed = crypto
				.createHash('sha256')
				.update('reann-rearm-seed')
				.digest();
			const { basepoints } = makeBasepoints(seed);
			const node = new LightningNode({
				nodePrivateKey: localNodePriv,
				channelBasepoints: basepoints,
				perCommitmentSeed: seed,
				fundingPrivkey: crypto
					.createHash('sha256')
					.update('reann-rearm-funding')
					.digest(),
				network: Network.REGTEST,
				chainBackend: backend
			});
			node.on('error', () => {});
			node.on('node:error', () => {});

			const { opener } = setupNormalChannels();
			const channelId = opener.getChannelId()!;
			const fundingTxid = opener.getFullState().fundingTxid!;
			node
				.getChannelManager()
				.restoreChannel(opener, remoteNodeId.toString('hex'));

			const rearmed: Array<{ cid: Buffer; txid: string }> = [];
			(node as any).chainWatcher.rearmAnnouncementTracking = (
				cid: Buffer,
				txid: string
			) => rearmed.push({ cid, txid });

			node.getChannelManager().emit('splice:complete', channelId);

			expect(rearmed.length).to.equal(1);
			expect(rearmed[0].cid.equals(channelId)).to.be.true;
			expect(rearmed[0].txid).to.equal(
				Buffer.from(fundingTxid).reverse().toString('hex')
			);
			node.destroy();
		});
	});

	describe('Funding spend detection across splice generations', function () {
		// Live mainnet bug #2 (channel 5e602dac): splices reuse the 2-of-2
		// funding script, so the script's history contains every funding
		// generation. checkFundingSpent only examined the FIRST non-self entry —
		// the ORIGINAL funding tx, which doesn't spend the watched outpoint — so
		// a real force-close of the post-splice funding went undetected forever.
		function makeChainedTxs(): {
			sharedScript: Buffer;
			txA: any;
			txB: any;
			txC: any;
		} {
			const bitcoinjs = require('bitcoinjs-lib');
			const sharedScript = Buffer.concat([
				Buffer.from([0x00, 0x20]),
				crypto.randomBytes(32)
			]); // P2WSH
			const txA = new bitcoinjs.Transaction(); // original funding
			txA.version = 2;
			txA.addInput(crypto.randomBytes(32), 0);
			txA.addOutput(
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
				5_000
			);
			txA.addOutput(sharedScript, 22_000); // funding @ vout 1
			const txB = new bitcoinjs.Transaction(); // splice tx
			txB.version = 2;
			txB.addInput(txA.getHash(), 1);
			txB.addOutput(sharedScript, 16_420); // new funding @ vout 0
			txB.addOutput(
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
				5_000
			);
			const txC = new bitcoinjs.Transaction(); // commitment (force-close)
			txC.version = 2;
			txC.addInput(txB.getHash(), 0);
			txC.addOutput(
				Buffer.concat([Buffer.from([0x00, 0x20]), crypto.randomBytes(32)]),
				15_476
			);
			return { sharedScript, txA, txB, txC };
		}

		async function runDetection(
			includeSpender: boolean
		): Promise<Array<{ txid: string; height: number }>> {
			const { ChainWatcher } = await import(
				'../../src/lightning/chain/chain-watcher'
			);
			const { txA, txB, txC } = makeChainedTxs();
			const txByid = new Map([
				[txA.getId(), txA],
				[txB.getId(), txB],
				[txC.getId(), txC]
			]);
			const history = [
				{ txid: txA.getId(), height: 953256 },
				{ txid: txB.getId(), height: 953266 },
				...(includeSpender ? [{ txid: txC.getId(), height: 953269 }] : [])
			];
			const backend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => history,
				getTransaction: async (txid: string) => txByid.get(txid)!.toBuffer(),
				broadcastTransaction: async () => ''
			};
			const detected: Array<{ txid: string; height: number }> = [];
			const fakeManager = {
				handleNewBlock: () => [],
				handleFundingConfirmed: () => {},
				handleFundingSpent: (_cid: Buffer, spendingTx: any, height: number) => {
					detected.push({ txid: spendingTx.getId(), height });
					return [];
				},
				on: () => {}
			};
			const watcher = new ChainWatcher({
				backend,
				channelManager: fakeManager as any
			});
			await (watcher as any).checkFundingSpent({
				channelId: crypto.randomBytes(32),
				txid: txB.getId(), // watching the POST-splice funding
				outputIndex: 0,
				minimumDepth: 3,
				scriptHash: 'ef'.repeat(32),
				confirmed: true,
				confirmationHeight: 953266,
				announcementTriggered: false
			});
			return includeSpender
				? detected.map((d) => ({ ...d, expectedTxid: txC.getId() }) as any)
				: detected;
		}

		it('detects the force-close even when earlier funding generations precede it in history', async function () {
			const detected = (await runDetection(true)) as any[];
			expect(detected.length, 'spend detected').to.equal(1);
			expect(detected[0].txid).to.equal(detected[0].expectedTxid);
			expect(detected[0].height).to.equal(953269);
		});

		it('does not report a spend when no history entry spends the watched outpoint', async function () {
			const detected = await runDetection(false);
			expect(detected.length).to.equal(0);
		});
	});

	describe('LightningNode SCID verification before signing', function () {
		function makeNode(merklePos: number | 'throw'): {
			node: LightningNode;
			triggered: Array<{ blockHeight: number; txIndex: number }>;
			channelId: Buffer;
		} {
			const backend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => '',
				getTransactionMerkleProof: async (_txid: string, height: number) => {
					if (merklePos === 'throw') throw new Error('backend down');
					return { blockHeight: height, txIndex: merklePos };
				}
			};
			const seed = crypto
				.createHash('sha256')
				.update('reann-node-seed')
				.digest();
			const { basepoints } = makeBasepoints(seed);
			const node = new LightningNode({
				nodePrivateKey: localNodePriv,
				channelBasepoints: basepoints,
				perCommitmentSeed: seed,
				fundingPrivkey: crypto
					.createHash('sha256')
					.update('reann-node-funding')
					.digest(),
				network: Network.REGTEST,
				chainBackend: backend
			});
			node.on('error', () => {});
			node.on('node:error', () => {});

			const { opener } = setupNormalChannels();
			const channelId = opener.getChannelId()!;
			node
				.getChannelManager()
				.restoreChannel(opener, remoteNodeId.toString('hex'));

			const triggered: Array<{ blockHeight: number; txIndex: number }> = [];
			node.getChannelManager().triggerAnnouncementDepth = ((
				cid: Buffer,
				blockHeight: number,
				txIndex: number
			) => {
				triggered.push({ blockHeight, txIndex });
			}) as any;
			return { node, triggered, channelId };
		}

		it('skips signing when the claimed tx index conflicts with the chain', async function () {
			const { node, triggered, channelId } = makeNode(847);
			await (node as any).signAnnouncementForScid(channelId, SCID_B); // claims 1174, chain says 847
			expect(triggered.length).to.equal(0);
			node.destroy();
		});

		it('signs when the claimed position matches the chain', async function () {
			const { node, triggered, channelId } = makeNode(1174);
			await (node as any).signAnnouncementForScid(channelId, SCID_B);
			expect(triggered).to.deep.equal([{ blockHeight: 953375, txIndex: 1174 }]);
			node.destroy();
		});

		it('proceeds when verification is unavailable (backend error)', async function () {
			const { node, triggered, channelId } = makeNode('throw');
			await (node as any).signAnnouncementForScid(channelId, SCID_B);
			expect(triggered.length).to.equal(1);
			node.destroy();
		});
	});
});
