/**
 * Pending-close resolution & fallback fund recovery
 *
 * 1. Channel.markResolved / ChannelManager.markChannelResolved — closing
 *    channels transition to CLOSED once their on-chain close fully resolves.
 * 2. LightningNode wiring — 'channel:resolved' transitions + persists, and
 *    restore() reconciles FORCE_CLOSED channels whose monitor is already
 *    FULLY_RESOLVED (stale rows from sessions that missed the event).
 * 3. ChainMonitor.setDestinationScript — rebuilds sweeps held for CSV/CLTV
 *    maturity so they pay the new (wallet-owned) destination, including
 *    across restore().
 * 4. LightningNode.recoverFallbackFunds — sweeps UTXOs stranded at the
 *    funding-key fallback address into the wallet sweep destination.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
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
import { buildLocalCommitment } from '../../src/lightning/channel/commitment-builder';
import { buildClosingTx } from '../../src/lightning/chain/closing';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ChainActionType,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	serializeChainMonitorState,
	deserializeChainMonitorState,
	serializePaymentInfo,
	deserializePaymentInfo
} from '../../src/lightning/storage/serialization';
import {
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import { Network } from '../../src/lightning/invoice/types';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;

// ─────────────── Helpers ───────────────

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		privkeys.push(privkey);
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
	acceptor: Channel;
	openerPrivkeys: Buffer[];
	openerBasepoints: IChannelBasepoints;
	openerCommitmentSeed: Buffer;
} {
	const openerSeed = Buffer.alloc(32, 0x51);
	const acceptorSeed = Buffer.alloc(32, 0x52);
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('resolution-opener'))
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update(Buffer.from('resolution-acceptor'))
		.digest();

	const { basepoints: openerBasepoints, privkeys: openerPrivkeys } =
		makeBasepoints(openerSeed);
	const { basepoints: acceptorBasepoints } = makeBasepoints(acceptorSeed);

	const openerState = createOpenerState({
		temporaryChannelId: Buffer.alloc(32, 0xdd),
		fundingSatoshis: 1_000_000n,
		pushMsat: 200_000_000n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: openerBasepoints,
		localPerCommitmentSeed: openerCommitmentSeed
	});
	const opener = new Channel(openerState);

	const acceptorState = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32, 0xdd),
		fundingSatoshis: 0n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: acceptorBasepoints,
		localPerCommitmentSeed: acceptorCommitmentSeed,
		remoteBasepoints: openerBasepoints,
		remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
	});
	const acceptor = new Channel(acceptorState);

	const openActions = opener.initiateOpen();
	const openMsg = findSendAction(openActions, MessageType.OPEN_CHANNEL);
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(openMsg.payload)
	);
	const acceptMsg = findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL);
	opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));

	const fundingTxid = crypto.randomBytes(32);
	const fakeSig = crypto.randomBytes(64);
	const fcActions = opener.createFundingCreated(fundingTxid, 0, fakeSig);
	const fcMsg = findSendAction(fcActions, MessageType.FUNDING_CREATED);
	const fsActions = acceptor.handleFundingCreated(
		decodeFundingCreatedMessage(fcMsg.payload),
		crypto.randomBytes(64)
	);
	const fsMsg = findSendAction(fsActions, MessageType.FUNDING_SIGNED);
	opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));

	const openerReadyActions = opener.fundingConfirmed();
	const openerReadyMsg = findSendAction(
		openerReadyActions,
		MessageType.CHANNEL_READY
	);
	acceptor.handleChannelReady(
		decodeChannelReadyMessage(openerReadyMsg.payload)
	);

	const acceptorReadyActions = acceptor.fundingConfirmed();
	const acceptorReadyMsg = findSendAction(
		acceptorReadyActions,
		MessageType.CHANNEL_READY
	);
	opener.handleChannelReady(
		decodeChannelReadyMessage(acceptorReadyMsg.payload)
	);

	expect(opener.getState()).to.equal(ChannelState.NORMAL);

	return {
		opener,
		acceptor,
		openerPrivkeys,
		openerBasepoints,
		openerCommitmentSeed
	};
}

function makeP2wpkhScript(pubkey: Buffer): Buffer {
	return bitcoin.payments.p2wpkh({ pubkey, network }).output!;
}

/** Minimal in-memory IStorageBackend (mirrors persistence-crash-safety). */
class MockStorage implements IStorageBackend {
	channels = new Map<string, { state: any; peerPubkey: string }>();
	chainMonitors = new Map<string, any>();

	open(): void {}
	close(): void {}
	saveChannel(id: string, state: any, peerPubkey: string): void {
		this.channels.set(id, { state, peerPubkey });
	}
	loadChannel(id: string): any {
		return this.channels.get(id) || null;
	}
	loadAllChannels(): Array<any> {
		return [...this.channels].map(([channelId, v]) => ({
			channelId,
			state: v.state,
			peerPubkey: v.peerPubkey
		}));
	}
	deleteChannel(id: string): void {
		this.channels.delete(id);
	}
	savePayment(): void {}
	loadPayment(): any {
		return null;
	}
	loadAllPayments(): Array<any> {
		return [];
	}
	deletePayment(): void {}
	savePreimage(): void {}
	loadPreimage(): Buffer | null {
		return null;
	}
	loadAllPreimages(): Array<any> {
		return [];
	}
	saveScidMapping(): void {}
	loadAllScidMappings(): Array<any> {
		return [];
	}
	saveHtlcPaymentMapping(): void {}
	loadAllHtlcPaymentMappings(): Array<any> {
		return [];
	}
	deleteHtlcPaymentMapping(): void {}
	saveForwardedHtlc(): void {}
	loadAllForwardedHtlcs(): Array<any> {
		return [];
	}
	deleteForwardedHtlc(): void {}
	saveChainMonitor(channelId: string, state: any): void {
		this.chainMonitors.set(channelId, state);
	}
	loadChainMonitor(channelId: string): any {
		return this.chainMonitors.get(channelId) || null;
	}
	loadAllChainMonitors(): Array<any> {
		return [...this.chainMonitors].map(([channelId, state]) => ({
			channelId,
			state
		}));
	}
	saveGossipChannel(): void {}
	loadAllGossipChannels(): any[] {
		return [];
	}
	saveGossipNode(): void {}
	loadAllGossipNodes(): any[] {
		return [];
	}
	savePaymentSecret(): void {}
	loadAllPaymentSecrets(): Array<{ paymentHashHex: string; secret: Buffer }> {
		return [];
	}
	deletePaymentSecret(): void {}
	saveInvoice(): void {}
	loadAllInvoices(): Array<any> {
		return [];
	}
	deleteInvoice(): void {}
	saveMissionControl(): void {}
	loadMissionControl(): string | null {
		return null;
	}
	savePeerAddress(): void {}
	loadAllPeerAddresses(): Array<{
		pubkey: string;
		host: string;
		port: number;
	}> {
		return [];
	}
	deletePeerAddress(): void {}
	saveChannelKeyIndex(): void {}
	loadChannelKeyIndex(): number | null {
		return null;
	}
	loadNextChannelIndex(): number {
		return 1;
	}
	saveMetadata(): void {}
	loadMetadata(): string | null {
		return null;
	}
	saveHtlcSharedSecret(): void {}
	deleteHtlcSharedSecret(): void {}
	loadAllHtlcSharedSecrets(): Array<{ key: string; secret: Buffer }> {
		return [];
	}
	transaction<T>(fn: () => T): T {
		return fn();
	}
}

function makeNodeKeys(tag: string): {
	nodePrivateKey: Buffer;
	basepoints: IChannelBasepoints;
	fundingPrivkey: Buffer;
	perCommitmentSeed: Buffer;
} {
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(`${tag}-funding`)
		.digest();
	const seed = crypto.createHash('sha256').update(`${tag}-seed`).digest();
	const { basepoints } = makeBasepoints(seed);
	// fundingPubkey must match fundingPrivkey for fallback recovery signing
	basepoints.fundingPubkey = getPublicKey(fundingPrivkey);
	return {
		nodePrivateKey: crypto.createHash('sha256').update(`${tag}-node`).digest(),
		basepoints,
		fundingPrivkey,
		perCommitmentSeed: seed
	};
}

// ─────────────── 1. markResolved ───────────────

describe('Pending-close resolution', function () {
	describe('Channel.markResolved', function () {
		it('transitions FORCE_CLOSED → CLOSED and is idempotent', function () {
			const { opener } = setupNormalChannels();
			expect(opener.markClosedOnChain(true)).to.be.true;
			expect(opener.getState()).to.equal(ChannelState.FORCE_CLOSED);

			expect(opener.markResolved()).to.be.true;
			expect(opener.getState()).to.equal(ChannelState.CLOSED);

			// Already CLOSED — no further transition
			expect(opener.markResolved()).to.be.false;
			expect(opener.getState()).to.equal(ChannelState.CLOSED);
		});

		it('is a no-op for channels not in a closing state', function () {
			const { opener } = setupNormalChannels();
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
			expect(opener.markResolved()).to.be.false;
			expect(opener.getState()).to.equal(ChannelState.NORMAL);
		});
	});

	describe('ChannelManager.markChannelResolved', function () {
		it('returns false for unknown channels', function () {
			const { basepoints, fundingPrivkey, perCommitmentSeed } =
				makeNodeKeys('mgr-unknown');
			const config: IChannelManagerConfig = {
				localBasepoints: basepoints,
				localPerCommitmentSeed: perCommitmentSeed,
				localFundingPrivkey: fundingPrivkey
			};
			const manager = new ChannelManager(config);
			expect(manager.markChannelResolved(crypto.randomBytes(32))).to.be.false;
		});

		it('transitions a registered FORCE_CLOSED channel to CLOSED', function () {
			const { opener, openerPrivkeys, openerBasepoints, openerCommitmentSeed } =
				setupNormalChannels();
			const config: IChannelManagerConfig = {
				localBasepoints: openerBasepoints,
				localPerCommitmentSeed: openerCommitmentSeed,
				localFundingPrivkey: openerPrivkeys[0]
			};
			const manager = new ChannelManager(config);
			const channelId = opener.getChannelId()!;
			(manager as any).channels.set(channelId.toString('hex'), opener);

			opener.markClosedOnChain(true);
			expect(manager.markChannelResolved(channelId)).to.be.true;
			expect(manager.getChannel(channelId)!.getState()).to.equal(
				ChannelState.CLOSED
			);
		});
	});

	// ─────────────── 2. LightningNode wiring ───────────────

	describe('LightningNode channel:resolved wiring', function () {
		it('transitions the channel to CLOSED, persists, and re-emits publicly', function () {
			const keys = makeNodeKeys('node-resolved');
			const storage = new MockStorage();
			const node = new LightningNode({
				nodePrivateKey: keys.nodePrivateKey,
				channelBasepoints: keys.basepoints,
				perCommitmentSeed: keys.perCommitmentSeed,
				fundingPrivkey: keys.fundingPrivkey,
				network: Network.REGTEST,
				storage
			});
			node.on('error', () => {});
			node.on('node:error', () => {});

			const { opener } = setupNormalChannels();
			opener.markClosedOnChain(true);
			const channelId = opener.getChannelId()!;
			node.getChannelManager().restoreChannel(opener, 'deadbeef'.repeat(8));

			let publicEvent: Buffer | null = null;
			node.on(
				'channel:resolved',
				({ channelId: cid }: { channelId: Buffer }) => {
					publicEvent = cid;
				}
			);

			node.getChannelManager().emit('channel:resolved', channelId);

			expect(opener.getState()).to.equal(ChannelState.CLOSED);
			expect(publicEvent).to.not.be.null;
			expect(publicEvent!.equals(channelId)).to.be.true;
			const saved = storage.channels.get(channelId.toString('hex'));
			expect(saved, 'channel persisted').to.exist;
			expect(saved!.state.state).to.equal(ChannelState.CLOSED);
			node.destroy();
		});

		it('reconciles a stale FORCE_CLOSED channel with a FULLY_RESOLVED monitor on restore', function () {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const channelId = opener.getChannelId()!;
			const channelIdHex = channelId.toString('hex');
			const destScript = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			// A cooperative-close spend resolves the monitor immediately.
			const closingResult = buildClosingTx({
				fundingTxid: state.fundingTxid!.toString('hex'),
				fundingOutputIndex: state.fundingOutputIndex,
				fundingAmount: state.fundingSatoshis,
				localScriptPubkey: destScript,
				remoteScriptPubkey: Buffer.alloc(22, 0x02),
				localAmount: 800_000n,
				remoteAmount: 199_000n,
				feeAmount: 1_000n
			});
			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);
			monitor.handleFundingSpent(closingResult.tx, 100);
			expect(monitor.isFullyResolved()).to.be.true;

			// Persist the stale shape: channel FORCE_CLOSED, monitor FULLY_RESOLVED.
			opener.markClosedOnChain(true);
			const storage = new MockStorage();
			storage.saveChannel(
				channelIdHex,
				opener.getFullState(),
				'deadbeef'.repeat(8)
			);
			storage.saveChainMonitor(channelIdHex, monitor.getFullState());

			const keys = makeNodeKeys('node-reconcile');
			const node = new LightningNode({
				nodePrivateKey: keys.nodePrivateKey,
				channelBasepoints: keys.basepoints,
				perCommitmentSeed: keys.perCommitmentSeed,
				fundingPrivkey: keys.fundingPrivkey,
				network: Network.REGTEST,
				storage
			});
			node.on('error', () => {});
			node.on('node:error', () => {});

			const restored = node.getChannelManager().getChannel(channelId);
			expect(restored, 'channel restored').to.exist;
			expect(restored!.getState()).to.equal(ChannelState.CLOSED);
			expect(storage.channels.get(channelIdHex)!.state.state).to.equal(
				ChannelState.CLOSED
			);
			node.destroy();
		});
	});

	// ─────────────── 3. Held sweep rebuild on destination change ───────────────

	describe('ChainMonitor held-sweep rebuild', function () {
		function setupHeldSweep(): {
			monitor: ChainMonitor;
			oldDest: Buffer;
			openerPrivkeys: Buffer[];
			state: ReturnType<Channel['getFullState']>;
		} {
			const { opener, openerPrivkeys } = setupNormalChannels();
			const state = opener.getFullState();
			const oldDest = makeP2wpkhScript(getPublicKey(openerPrivkeys[0]));

			const monitor = new ChainMonitor(
				state,
				oldDest,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);
			const perCommitmentSecret = generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - state.localCommitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);
			const built = buildLocalCommitment(state, perCommitmentPoint);

			// Our commitment confirms; to_local sweep is built but held for CSV.
			monitor.handleFundingSpent(built.result.tx, 100);
			return { monitor, oldDest, openerPrivkeys, state };
		}

		function heldToLocal(monitor: ChainMonitor): any {
			const o = monitor
				.getTrackedOutputs()
				.find((t) => t.outputType === OutputType.TO_LOCAL);
			expect(o, 'to_local tracked').to.exist;
			return o!;
		}

		it('setDestinationScript re-points a held sweep to the new destination', function () {
			const { monitor, oldDest, openerPrivkeys } = setupHeldSweep();
			const out = heldToLocal(monitor);
			expect(out.status).to.equal(OutputStatus.CONFIRMED);
			const originalMaturity = out.maturityHeight;

			const oldSweep = bitcoin.Transaction.fromHex(out.sweepTxHex!);
			expect(oldSweep.outs[0].script.equals(oldDest)).to.be.true;

			const newDest = makeP2wpkhScript(getPublicKey(openerPrivkeys[3]));
			monitor.setDestinationScript(newDest);

			const rebuilt = bitcoin.Transaction.fromHex(
				heldToLocal(monitor).sweepTxHex!
			);
			expect(rebuilt.outs[0].script.equals(newDest)).to.be.true;
			// Same input + sequence → same maturity
			expect(heldToLocal(monitor).maturityHeight).to.equal(originalMaturity);
			expect(rebuilt.ins[0].sequence).to.equal(oldSweep.ins[0].sequence);
		});

		it('releases the REBUILT sweep at maturity', function () {
			const { monitor, openerPrivkeys } = setupHeldSweep();
			const newDest = makeP2wpkhScript(getPublicKey(openerPrivkeys[3]));
			monitor.setDestinationScript(newDest);

			const maturity = heldToLocal(monitor).maturityHeight!;
			const actions = monitor.handleNewBlock(maturity);
			const broadcast = actions.filter(
				(a) => a.type === ChainActionType.BROADCAST_TX
			);
			expect(broadcast.length).to.equal(1);
			const tx = bitcoin.Transaction.fromBuffer((broadcast[0] as any).tx);
			expect(tx.outs[0].script.equals(newDest)).to.be.true;
		});

		it('setting the same destination is a no-op', function () {
			const { monitor, oldDest } = setupHeldSweep();
			const before = heldToLocal(monitor).sweepTxHex;
			monitor.setDestinationScript(Buffer.from(oldDest));
			expect(heldToLocal(monitor).sweepTxHex).to.equal(before);
		});

		it('does not touch already-broadcast sweeps', function () {
			const { monitor, oldDest, openerPrivkeys } = setupHeldSweep();
			const out = heldToLocal(monitor);
			// Simulate the sweep having been broadcast already.
			out.status = OutputStatus.SPEND_BROADCAST;
			out.broadcastHeight = 101;
			const before = out.sweepTxHex;

			monitor.setDestinationScript(
				makeP2wpkhScript(getPublicKey(openerPrivkeys[3]))
			);
			expect(heldToLocal(monitor).sweepTxHex).to.equal(before);
			const tx = bitcoin.Transaction.fromHex(heldToLocal(monitor).sweepTxHex!);
			expect(tx.outs[0].script.equals(oldDest)).to.be.true;
		});

		it('restore() rebuilds held sweeps against the new session destination', function () {
			const { monitor, openerPrivkeys, state } = setupHeldSweep();
			const saved = monitor.getFullState();

			const newDest = makeP2wpkhScript(getPublicKey(openerPrivkeys[3]));
			const restored = ChainMonitor.restore(
				saved,
				state,
				newDest,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);
			const out = restored
				.getTrackedOutputs()
				.find((t) => t.outputType === OutputType.TO_LOCAL)!;
			expect(out.status).to.equal(OutputStatus.CONFIRMED);
			const tx = bitcoin.Transaction.fromHex(out.sweepTxHex!);
			expect(tx.outs[0].script.equals(newDest)).to.be.true;
		});

		it('monitor state round-trips Buffers through serialize/deserialize', function () {
			const { monitor, openerPrivkeys, state } = setupHeldSweep();
			const revived = deserializeChainMonitorState(
				serializeChainMonitorState(monitor.getFullState())
			);
			const out = revived.trackedOutputs.find(
				(t) => t.outputType === OutputType.TO_LOCAL
			)!;
			expect(
				Buffer.isBuffer(out.witnessScript),
				'witnessScript revived as Buffer'
			).to.be.true;
			expect(typeof revived.commitmentBroadcast!.commitmentNumber).to.equal(
				'bigint'
			);

			const newDest = makeP2wpkhScript(getPublicKey(openerPrivkeys[3]));
			const restored = ChainMonitor.restore(
				revived,
				state,
				newDest,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);
			const rebuilt = restored
				.getTrackedOutputs()
				.find((t) => t.outputType === OutputType.TO_LOCAL)!;
			expect(
				bitcoin.Transaction.fromHex(rebuilt.sweepTxHex!).outs[0].script.equals(
					newDest
				)
			).to.be.true;
		});

		it('revives legacy rows where Buffers were persisted in raw toJSON form', function () {
			// Pre-fix serializer: Buffer.isBuffer never matched in the replacer
			// (JSON.stringify calls Buffer.prototype.toJSON first), so DB rows hold
			// { type: 'Buffer', data: [...] } objects. Restoring such a row and
			// rebuilding its held sweep crashed startup with a typeforce error.
			const { monitor, openerPrivkeys, state } = setupHeldSweep();
			const legacyJson = JSON.stringify(monitor.getFullState(), (_, v) =>
				typeof v === 'bigint' ? `__bigint__${v.toString()}` : v
			);
			const revived = deserializeChainMonitorState(legacyJson);
			const out = revived.trackedOutputs.find(
				(t) => t.outputType === OutputType.TO_LOCAL
			)!;
			expect(Buffer.isBuffer(out.witnessScript), 'legacy witnessScript revived')
				.to.be.true;

			const newDest = makeP2wpkhScript(getPublicKey(openerPrivkeys[3]));
			const restored = ChainMonitor.restore(
				revived,
				state,
				newDest,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);
			const rebuilt = restored
				.getTrackedOutputs()
				.find((t) => t.outputType === OutputType.TO_LOCAL)!;
			expect(
				bitcoin.Transaction.fromHex(rebuilt.sweepTxHex!).outs[0].script.equals(
					newDest
				)
			).to.be.true;
		});

		it('payment route Buffers survive serialize/deserialize (incl. legacy rows)', function () {
			// Same toJSON-before-replacer pitfall as monitor state: route hop
			// pubkeys/scids must come back as Buffers, including from legacy rows.
			const payment = {
				paymentHash: crypto.randomBytes(32),
				amountMsat: 1_000_000n,
				status: 'PENDING',
				direction: 'OUTBOUND',
				createdAt: 1,
				route: {
					hops: [
						{
							pubkey: crypto.randomBytes(33),
							shortChannelId: crypto.randomBytes(8),
							amountToForwardMsat: 999_000n,
							outgoingCltvValue: 100,
							feeBaseMsat: 1000,
							feeProportionalMillionths: 1,
							cltvExpiryDelta: 40
						}
					],
					totalAmountMsat: 1_000_000n,
					totalCltvDelta: 40,
					totalFeeMsat: 1_000n
				}
			};
			const revived = deserializePaymentInfo(
				serializePaymentInfo(payment as never)
			);
			const hop = revived.route!.hops[0];
			expect(Buffer.isBuffer(hop.pubkey)).to.be.true;
			expect(hop.pubkey.equals(payment.route.hops[0].pubkey)).to.be.true;
			expect(Buffer.isBuffer(hop.shortChannelId)).to.be.true;
			expect(hop.amountToForwardMsat).to.equal(999_000n);

			// Legacy row: route stringified with bigint-only replacer (raw toJSON Buffers)
			const legacy = serializePaymentInfo(payment as never);
			legacy.route = JSON.stringify(payment.route, (_, v) =>
				typeof v === 'bigint' ? `__bigint__${v.toString()}` : v
			);
			const legacyRevived = deserializePaymentInfo(legacy);
			expect(Buffer.isBuffer(legacyRevived.route!.hops[0].pubkey)).to.be.true;
			expect(
				legacyRevived.route!.hops[0].pubkey.equals(payment.route.hops[0].pubkey)
			).to.be.true;
		});

		it('restore() never throws when a held sweep cannot be rebuilt', function () {
			const { monitor, openerPrivkeys, state } = setupHeldSweep();
			const saved = monitor.getFullState();
			// Corrupt the witness script so the resolver cannot rebuild the sweep.
			const out = saved.trackedOutputs.find(
				(t) => t.outputType === OutputType.TO_LOCAL
			)!;
			const originalHex = out.sweepTxHex!;
			out.witnessScript = {
				type: 'Buffer',
				data: 'garbage'
			} as unknown as Buffer;

			const newDest = makeP2wpkhScript(getPublicKey(openerPrivkeys[3]));
			const restored = ChainMonitor.restore(
				saved,
				state,
				newDest,
				10,
				openerPrivkeys[1],
				openerPrivkeys[2],
				network
			);
			// The held sweep survives unchanged — still broadcastable at maturity.
			const kept = restored
				.getTrackedOutputs()
				.find((t) => t.outputType === OutputType.TO_LOCAL)!;
			expect(kept.sweepTxHex).to.equal(originalHex);
		});
	});

	// ─────────────── 4. recoverFallbackFunds ───────────────

	describe('LightningNode.recoverFallbackFunds', function () {
		function makeBackend(
			utxos: Array<{
				txid: string;
				outputIndex: number;
				valueSat: number;
				height: number;
			}>
		): {
			backend: IChainBackend & {
				listUnspent: (sh: string) => Promise<typeof utxos>;
			};
			broadcasts: string[];
			listedScriptHashes: string[];
		} {
			const broadcasts: string[] = [];
			const listedScriptHashes: string[] = [];
			const backend = {
				subscribeToHeaders: async (): Promise<void> => {},
				subscribeToScriptHash: async (): Promise<void> => {},
				getScriptHashHistory: async (): Promise<
					Array<{ txid: string; height: number }>
				> => [],
				getTransaction: async (): Promise<Buffer> => Buffer.alloc(0),
				broadcastTransaction: async (rawTxHex: string): Promise<string> => {
					broadcasts.push(rawTxHex);
					return bitcoin.Transaction.fromHex(rawTxHex).getId();
				},
				listUnspent: async (scriptHash: string): Promise<typeof utxos> => {
					listedScriptHashes.push(scriptHash);
					return utxos;
				}
			};
			return { backend, broadcasts, listedScriptHashes };
		}

		function makeNode(opts: {
			tag: string;
			backend?: IChainBackend;
			sweepDestinationScript?: Buffer;
		}): { node: LightningNode; fundingPubkey: Buffer } {
			const keys = makeNodeKeys(opts.tag);
			const node = new LightningNode({
				nodePrivateKey: keys.nodePrivateKey,
				channelBasepoints: keys.basepoints,
				perCommitmentSeed: keys.perCommitmentSeed,
				fundingPrivkey: keys.fundingPrivkey,
				network: Network.REGTEST,
				chainBackend: opts.backend,
				sweepDestinationScript: opts.sweepDestinationScript
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			return { node, fundingPubkey: keys.basepoints.fundingPubkey };
		}

		const walletDest = makeP2wpkhScript(
			getPublicKey(crypto.createHash('sha256').update('wallet-dest').digest())
		);

		it('sweeps all fallback UTXOs into the wallet destination in one signed tx', async function () {
			const utxos = [
				{
					txid: crypto.randomBytes(32).toString('hex'),
					outputIndex: 0,
					valueSat: 50_000,
					height: 100
				},
				{
					txid: crypto.randomBytes(32).toString('hex'),
					outputIndex: 1,
					valueSat: 30_000,
					height: 101
				}
			];
			const { backend, broadcasts, listedScriptHashes } = makeBackend(utxos);
			const { node, fundingPubkey } = makeNode({
				tag: 'recover-ok',
				backend,
				sweepDestinationScript: walletDest
			});

			const result = await node.recoverFallbackFunds({ feeRatePerVbyte: 5 });
			expect(result).to.not.be.null;
			expect(result!.inputCount).to.equal(2);

			// Queried the funding-key fallback scripthash
			const fallbackScript = bitcoin.payments.p2wpkh({ pubkey: fundingPubkey })
				.output!;
			expect(listedScriptHashes).to.deep.equal([
				computeScriptHash(fallbackScript)
			]);

			// One broadcast spending both UTXOs to the wallet destination
			expect(broadcasts.length).to.equal(1);
			const tx = bitcoin.Transaction.fromHex(broadcasts[0]);
			expect(tx.ins.length).to.equal(2);
			expect(tx.outs.length).to.equal(1);
			expect(tx.outs[0].script.equals(walletDest)).to.be.true;

			const expectedFee = Math.ceil(5 * (11 + 31 + 68 * 2));
			expect(tx.outs[0].value).to.equal(80_000 - expectedFee);
			expect(result!.amountSat).to.equal(80_000 - expectedFee);
			expect(result!.txid).to.equal(tx.getId());

			// P2WPKH witness: [signature, pubkey]
			for (const input of tx.ins) {
				expect(input.witness.length).to.equal(2);
				expect(Buffer.from(input.witness[1]).equals(fundingPubkey)).to.be.true;
			}
			node.destroy();
		});

		it('returns null when no wallet destination is configured', async function () {
			const { backend } = makeBackend([
				{
					txid: crypto.randomBytes(32).toString('hex'),
					outputIndex: 0,
					valueSat: 50_000,
					height: 100
				}
			]);
			const { node } = makeNode({ tag: 'recover-nodest', backend });
			expect(await node.recoverFallbackFunds()).to.be.null;
			node.destroy();
		});

		it('returns null when the fallback address has no UTXOs', async function () {
			const { backend, broadcasts } = makeBackend([]);
			const { node } = makeNode({
				tag: 'recover-empty',
				backend,
				sweepDestinationScript: walletDest
			});
			expect(await node.recoverFallbackFunds({ feeRatePerVbyte: 5 })).to.be
				.null;
			expect(broadcasts.length).to.equal(0);
			node.destroy();
		});

		it('returns null when the recoverable amount would be dust after fees', async function () {
			const { backend, broadcasts } = makeBackend([
				{
					txid: crypto.randomBytes(32).toString('hex'),
					outputIndex: 0,
					valueSat: 1_000,
					height: 100
				}
			]);
			const { node } = makeNode({
				tag: 'recover-dust',
				backend,
				sweepDestinationScript: walletDest
			});
			expect(await node.recoverFallbackFunds({ feeRatePerVbyte: 5 })).to.be
				.null;
			expect(broadcasts.length).to.equal(0);
			node.destroy();
		});

		it('returns null when the destination IS the fallback script (nothing to redirect)', async function () {
			const keys = makeNodeKeys('recover-self');
			const fallbackScript = bitcoin.payments.p2wpkh({
				pubkey: keys.basepoints.fundingPubkey
			}).output!;
			const { backend, broadcasts } = makeBackend([
				{
					txid: crypto.randomBytes(32).toString('hex'),
					outputIndex: 0,
					valueSat: 50_000,
					height: 100
				}
			]);
			const node = new LightningNode({
				nodePrivateKey: keys.nodePrivateKey,
				channelBasepoints: keys.basepoints,
				perCommitmentSeed: keys.perCommitmentSeed,
				fundingPrivkey: keys.fundingPrivkey,
				network: Network.REGTEST,
				chainBackend: backend,
				sweepDestinationScript: fallbackScript
			});
			node.on('error', () => {});
			node.on('node:error', () => {});
			expect(await node.recoverFallbackFunds({ feeRatePerVbyte: 5 })).to.be
				.null;
			expect(broadcasts.length).to.equal(0);
			node.destroy();
		});

		it('returns null when the backend has no listUnspent support', async function () {
			const backend: IChainBackend = {
				subscribeToHeaders: async () => {},
				subscribeToScriptHash: async () => {},
				getScriptHashHistory: async () => [],
				getTransaction: async () => Buffer.alloc(0),
				broadcastTransaction: async () => ''
			};
			const { node } = makeNode({
				tag: 'recover-nolist',
				backend,
				sweepDestinationScript: walletDest
			});
			expect(await node.recoverFallbackFunds({ feeRatePerVbyte: 5 })).to.be
				.null;
			node.destroy();
		});
	});
});
