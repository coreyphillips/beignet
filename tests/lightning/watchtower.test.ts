import { expect } from 'chai';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	BITCOIN_CHAIN_HASH,
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
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
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { buildToLocalScript } from '../../src/lightning/script/commitment';
import { buildToRemoteAnchorScript } from '../../src/lightning/script/anchor';
import {
	deriveRevocationPubkey,
	derivePublicKey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { MAX_INDEX } from '../../src/lightning/keys/shachain';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	WtMessageType,
	CreateSessionCode,
	StateUpdateCode,
	encodeInit,
	decodeInit,
	encodeError,
	decodeError,
	encodeCreateSession,
	decodeCreateSession,
	encodeCreateSessionReply,
	decodeCreateSessionReply,
	encodeStateUpdate,
	decodeStateUpdate,
	encodeStateUpdateReply,
	decodeStateUpdateReply,
	encodeDeleteSessionReply,
	decodeDeleteSessionReply
} from '../../src/lightning/watchtower/wtwire';
import {
	breachHintFromTxid,
	breachKeyFromTxid,
	encodeJusticeKitV0,
	decodeJusticeKitV0,
	encryptJusticeKitV0,
	decryptJusticeKitV0,
	IJusticeKitV0,
	V0_PLAINTEXT_SIZE,
	BlobType
} from '../../src/lightning/watchtower/blob';
import {
	buildJusticeBackup,
	IJusticeContext
} from '../../src/lightning/watchtower/justice';
import {
	WatchtowerClient,
	IWatchtowerStore
} from '../../src/lightning/watchtower/watchtower-client';
import { parseTowerUri } from '../../src/lightning/watchtower/tower-connection';
import {
	ITowerAddress,
	ITowerTransport,
	IWatchtowerSession,
	IWatchtowerUpdate
} from '../../src/lightning/watchtower/types';
import { chainHashForNetwork } from '../../src/lightning/watchtower';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;

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
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

/** One commitment round; returns the secret the acceptor revealed to the opener. */
function exchangeOnce(opener: Channel, acceptor: Channel): Buffer {
	const csActions = opener.signCommitment(crypto.randomBytes(64), []);
	const csMsg = findSendAction(csActions, MessageType.COMMITMENT_SIGNED);
	const raaActions = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(csMsg.payload)
	);
	const raaMsg = findSendAction(raaActions, MessageType.REVOKE_AND_ACK);
	const raa = decodeRevokeAndAckMessage(raaMsg.payload);
	opener.handleRevokeAndAck(raa);
	return raa.perCommitmentSecret;
}

/** Build a justice context from a real revoked commitment (opener's view). */
function buildRevokedContext(sweepScript: Buffer): {
	ctx: IJusticeContext;
	revocationPubkey: Buffer;
	theirDelayed: Buffer;
	toSelfDelay: number;
	toLocalValue: number;
} {
	// Drive a real revocation using two fresh channels (deterministic seeds).
	const pair = freshPair();
	exchangeOnce(pair.opener, pair.acceptor);
	const state = pair.opener.getFullState();

	const secret = state.shaChainStore.getSecret(MAX_INDEX - 0n);
	expect(secret, 'revoked secret 0 present').to.not.be.null;
	const revokedPoint = perCommitmentPointFromSecret(secret!);
	const built = buildRemoteCommitment(state, revokedPoint, 0n);
	const revokedTx = built.result.tx;

	const revocationPubkey = deriveRevocationPubkey(
		state.localBasepoints.revocationBasepoint,
		revokedPoint
	);
	const theirDelayed = derivePublicKey(
		state.remoteBasepoints!.delayedPaymentBasepoint,
		revokedPoint
	);
	const toLocalScript = buildToLocalScript(
		revocationPubkey,
		theirDelayed,
		state.localConfig.toSelfDelay
	);
	const toLocalSpk = bitcoin.payments.p2wsh({
		redeem: { output: toLocalScript },
		network
	}).output!;
	let toLocalValue = 0;
	for (const o of revokedTx.outs) {
		if (o.script.equals(toLocalSpk)) toLocalValue = o.value;
	}

	const ctx: IJusticeContext = {
		channelId: 'wt-test',
		revokedTx,
		perCommitmentSecret: secret!,
		revocationBasepoint: state.localBasepoints.revocationBasepoint,
		revocationBasepointSecret: pair.openerPrivkeys[1],
		remoteDelayedBasepoint: state.remoteBasepoints!.delayedPaymentBasepoint,
		toSelfDelay: state.localConfig.toSelfDelay,
		isAnchor: false,
		localPaymentPubkey: state.localBasepoints.paymentBasepoint,
		paymentBasepointSecret: pair.openerPrivkeys[2],
		sweepScript,
		network
	};
	return {
		ctx,
		revocationPubkey,
		theirDelayed,
		toSelfDelay: state.localConfig.toSelfDelay,
		toLocalValue
	};
}

function freshPair(): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
} {
	const openerCommitmentSeed = crypto
		.createHash('sha256')
		.update('wt-opener')
		.digest();
	const acceptorCommitmentSeed = crypto
		.createHash('sha256')
		.update('wt-acceptor')
		.digest();
	const { basepoints: openerBp, privkeys: openerPrivkeys } = makeBasepoints(
		Buffer.alloc(32, 0x11)
	);
	const { basepoints: acceptorBp } = makeBasepoints(Buffer.alloc(32, 0x22));
	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xbb),
			fundingSatoshis: 1_000_000n,
			pushMsat: 200_000_000n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBp,
			localPerCommitmentSeed: openerCommitmentSeed
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: Buffer.alloc(32, 0xbb),
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBp,
			localPerCommitmentSeed: acceptorCommitmentSeed,
			remoteBasepoints: openerBp,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
	const openMsg = findSendAction(
		opener.initiateOpen(),
		MessageType.OPEN_CHANNEL
	);
	const acceptMsg = findSendAction(
		acceptor.handleOpenChannel(decodeOpenChannelMessage(openMsg.payload)),
		MessageType.ACCEPT_CHANNEL
	);
	opener.handleAcceptChannel(decodeAcceptChannelMessage(acceptMsg.payload));
	const fcMsg = findSendAction(
		opener.createFundingCreated(
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		),
		MessageType.FUNDING_CREATED
	);
	const fsMsg = findSendAction(
		acceptor.handleFundingCreated(
			decodeFundingCreatedMessage(fcMsg.payload),
			crypto.randomBytes(64)
		),
		MessageType.FUNDING_SIGNED
	);
	opener.handleFundingSigned(decodeFundingSignedMessage(fsMsg.payload));
	const oReady = findSendAction(
		opener.fundingConfirmed(),
		MessageType.CHANNEL_READY
	);
	acceptor.handleChannelReady(decodeChannelReadyMessage(oReady.payload));
	const aReady = findSendAction(
		acceptor.fundingConfirmed(),
		MessageType.CHANNEL_READY
	);
	opener.handleChannelReady(decodeChannelReadyMessage(aReady.payload));
	return { opener, acceptor, openerPrivkeys };
}

function p2wpkhScript(): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(crypto.randomBytes(32)),
		network
	}).output!;
}

describe('watchtower wtwire codecs', function () {
	it('round-trips Init', function () {
		const msg = {
			connFeatures: Buffer.from([0x02]),
			chainHash: chainHashForNetwork(network)
		};
		expect(decodeInit(encodeInit(msg))).to.deep.equal(msg);
	});

	it('round-trips Error', function () {
		const msg = { code: 50, data: Buffer.from('boom') };
		expect(decodeError(encodeError(msg))).to.deep.equal(msg);
	});

	it('round-trips CreateSession', function () {
		const msg = {
			blobType: BlobType.ALTRUIST_COMMIT,
			maxUpdates: 1024,
			rewardBase: 0,
			rewardRate: 0,
			sweepFeeRate: 2500n
		};
		expect(decodeCreateSession(encodeCreateSession(msg))).to.deep.equal(msg);
	});

	it('round-trips CreateSessionReply', function () {
		const msg = {
			code: CreateSessionCode.OK,
			lastApplied: 7,
			data: Buffer.alloc(0)
		};
		expect(
			decodeCreateSessionReply(encodeCreateSessionReply(msg))
		).to.deep.equal(msg);
	});

	it('round-trips StateUpdate', function () {
		const msg = {
			seqNum: 3,
			lastApplied: 2,
			isComplete: 0,
			hint: crypto.randomBytes(16),
			encryptedBlob: crypto.randomBytes(314)
		};
		expect(decodeStateUpdate(encodeStateUpdate(msg))).to.deep.equal(msg);
	});

	it('round-trips StateUpdateReply', function () {
		const msg = { code: StateUpdateCode.OK, lastApplied: 9 };
		expect(decodeStateUpdateReply(encodeStateUpdateReply(msg))).to.deep.equal(
			msg
		);
	});

	it('uses LND StateUpdateCode wire values 70/71/72 (S-W.H1)', function () {
		// These MUST match LND's wtwire StateUpdateCode block exactly. At 40/41/42
		// a full session's MAX_UPDATES_EXCEEDED reply never matched (protection
		// silently stopped) and CLIENT_BEHIND collided with the generic
		// TEMPORARY_FAILURE code (40), wrongly rewinding seqNum.
		expect(StateUpdateCode.CLIENT_BEHIND).to.equal(70);
		expect(StateUpdateCode.MAX_UPDATES_EXCEEDED).to.equal(71);
		expect(StateUpdateCode.SEQ_NUM_OUT_OF_ORDER).to.equal(72);
		// No collision with the generic temporary-failure code (40).
		expect(StateUpdateCode.CLIENT_BEHIND).to.not.equal(40);

		// And they land on the wire as the LND bytes.
		const wire = encodeStateUpdateReply({
			code: StateUpdateCode.MAX_UPDATES_EXCEEDED,
			lastApplied: 3
		});
		expect(wire.readUInt16BE(0)).to.equal(71);
		expect(
			decodeStateUpdateReply(Buffer.from('00470005', 'hex')).code
		).to.equal(StateUpdateCode.MAX_UPDATES_EXCEEDED);
	});

	it('round-trips DeleteSessionReply', function () {
		const msg = { code: 0 };
		expect(
			decodeDeleteSessionReply(encodeDeleteSessionReply(msg))
		).to.deep.equal(msg);
	});
});

describe('watchtower justice blob', function () {
	it('derives LND breach hint/key from txid (SHA256 / SHA256x2)', function () {
		const txid = crypto.randomBytes(32);
		expect(breachHintFromTxid(txid)).to.deep.equal(
			crypto.createHash('sha256').update(txid).digest().subarray(0, 16)
		);
		expect(breachKeyFromTxid(txid)).to.deep.equal(
			crypto.createHash('sha256').update(txid).update(txid).digest()
		);
	});

	it('encodes a v0 kit to a constant 274-byte plaintext and round-trips', function () {
		const kit: IJusticeKitV0 = {
			sweepAddress: p2wpkhScript(),
			revocationPubKey: getPublicKey(crypto.randomBytes(32)),
			localDelayPubKey: getPublicKey(crypto.randomBytes(32)),
			csvDelay: 144,
			commitToLocalSig: crypto.randomBytes(64),
			commitToRemotePubKey: getPublicKey(crypto.randomBytes(32)),
			commitToRemoteSig: crypto.randomBytes(64)
		};
		const pt = encodeJusticeKitV0(kit);
		expect(pt.length).to.equal(V0_PLAINTEXT_SIZE);
		expect(decodeJusticeKitV0(pt)).to.deep.equal(kit);
	});

	it('drops a blank to-remote pubkey on decode', function () {
		const kit: IJusticeKitV0 = {
			sweepAddress: p2wpkhScript(),
			revocationPubKey: getPublicKey(crypto.randomBytes(32)),
			localDelayPubKey: getPublicKey(crypto.randomBytes(32)),
			csvDelay: 144,
			commitToLocalSig: crypto.randomBytes(64)
		};
		const decoded = decodeJusticeKitV0(encodeJusticeKitV0(kit));
		expect(decoded.commitToRemotePubKey).to.be.undefined;
	});

	it('encrypts/decrypts a v0 kit under the breach key', function () {
		const kit: IJusticeKitV0 = {
			sweepAddress: p2wpkhScript(),
			revocationPubKey: getPublicKey(crypto.randomBytes(32)),
			localDelayPubKey: getPublicKey(crypto.randomBytes(32)),
			csvDelay: 144,
			commitToLocalSig: crypto.randomBytes(64)
		};
		const key = breachKeyFromTxid(crypto.randomBytes(32));
		const blob = encryptJusticeKitV0(kit, key);
		expect(decryptJusticeKitV0(blob, key)).to.deep.equal(kit);
	});

	it('fails to decrypt under the wrong key', function () {
		const kit: IJusticeKitV0 = {
			sweepAddress: p2wpkhScript(),
			revocationPubKey: getPublicKey(crypto.randomBytes(32)),
			localDelayPubKey: getPublicKey(crypto.randomBytes(32)),
			csvDelay: 144,
			commitToLocalSig: crypto.randomBytes(64)
		};
		const blob = encryptJusticeKitV0(
			kit,
			breachKeyFromTxid(crypto.randomBytes(32))
		);
		expect(() =>
			decryptJusticeKitV0(blob, breachKeyFromTxid(crypto.randomBytes(32)))
		).to.throw();
	});
});

describe('watchtower justice against a REAL revoked commitment', function () {
	it('blob sweep data matches the chain-monitor justice path', function () {
		const sweepScript = p2wpkhScript();
		const built = buildRevokedContext(sweepScript);
		const { revocationPubkey, theirDelayed, toSelfDelay, toLocalValue } = built;
		// Sweep only the to_local penalty here so the reconstructed justice tx is
		// single-input and deterministic; the to_remote path is covered below.
		const ctx: IJusticeContext = {
			...built.ctx,
			localPaymentPubkey: undefined,
			paymentBasepointSecret: undefined
		};

		const backup = buildJusticeBackup(ctx, {
			blobType: BlobType.ALTRUIST_COMMIT,
			sweepFeeRate: 2500n
		});

		// hint + key derive from the revoked txid (internal byte order).
		const revokedTxid = Buffer.from(ctx.revokedTx.getId(), 'hex').reverse();
		expect(backup.hint).to.deep.equal(breachHintFromTxid(revokedTxid));
		const kit = decryptJusticeKitV0(
			backup.encryptedBlob,
			breachKeyFromTxid(revokedTxid)
		);

		// Sweep data must equal exactly what chain-monitor's own penalty derives.
		expect(kit.revocationPubKey).to.deep.equal(revocationPubkey);
		expect(kit.localDelayPubKey).to.deep.equal(theirDelayed);
		expect(kit.csvDelay).to.equal(toSelfDelay);
		expect(kit.sweepAddress).to.deep.equal(sweepScript);

		// The to_local script the tower rebuilds must be the P2WSH on the revoked tx.
		const toLocalScript = buildToLocalScript(
			kit.revocationPubKey,
			kit.localDelayPubKey,
			kit.csvDelay
		);
		const toLocalSpk = bitcoin.payments.p2wsh({
			redeem: { output: toLocalScript },
			network
		}).output!;
		const outIdx = ctx.revokedTx.outs.findIndex((o) =>
			o.script.equals(toLocalSpk)
		);
		expect(outIdx, 'to_local output located on revoked tx').to.be.gte(0);

		// Reassemble the justice tx exactly as a tower would and verify the
		// pre-signed to_local signature validates (SIGHASH_ALL over that tx).
		const witnessLegacy = 156; // ToLocalPenaltyWitnessSize - 1 (legacy)
		const strippedNoRemote =
			8 + 1 + 41 + 1 + (sweepScript.length === 22 ? 31 : 43);
		const weight = strippedNoRemote * 4 + 2 + witnessLegacy;
		const fee = (2500n * BigInt(weight)) / 1000n;
		const jtx = new bitcoin.Transaction();
		jtx.version = 2;
		jtx.addInput(revokedTxid, outIdx, 0);
		jtx.addOutput(sweepScript, toLocalValue - Number(fee));
		const sighash = jtx.hashForWitnessV0(
			0,
			toLocalScript,
			toLocalValue,
			bitcoin.Transaction.SIGHASH_ALL
		);
		expect(ecc.verify(sighash, kit.revocationPubKey, kit.commitToLocalSig)).to
			.be.true;
		expect(backup.sweptSats).to.equal(BigInt(toLocalValue) - fee);
	});

	it('includes the legacy to_remote output when we hold one', function () {
		const built = buildRevokedContext(p2wpkhScript());
		const backup = buildJusticeBackup(built.ctx, {
			blobType: BlobType.ALTRUIST_COMMIT,
			sweepFeeRate: 2500n
		});
		const revokedTxid = Buffer.from(
			built.ctx.revokedTx.getId(),
			'hex'
		).reverse();
		const kit = decryptJusticeKitV0(
			backup.encryptedBlob,
			breachKeyFromTxid(revokedTxid)
		);
		expect(kit.commitToRemotePubKey).to.deep.equal(
			built.ctx.localPaymentPubkey
		);
		expect(kit.commitToRemoteSig).to.have.length(64);
		// Both outputs swept: total exceeds the to_local alone.
		expect(Number(backup.sweptSats)).to.be.greaterThan(built.toLocalValue);
	});

	it('the channel caches the revoked tx and returns it by revealed secret', function () {
		const pair = freshPair();
		// Two rounds: the first revoke reveals the funding-state point (never
		// signed via signCommitment, so never cached); the second reveals the
		// commitment we signed and cached in round one.
		exchangeOnce(pair.opener, pair.acceptor);
		const secret = exchangeOnce(pair.opener, pair.acceptor);

		// The channel-manager calls this on a clean revoke; it must return the
		// revoked remote commitment keyed by the revealed secret's point.
		const revokedTx = pair.opener.takeRevokedCommitmentTx(secret);
		expect(revokedTx, 'cached revoked tx returned').to.not.be.null;
		const tx = bitcoin.Transaction.fromBuffer(revokedTx!);
		const revokedPoint = perCommitmentPointFromSecret(secret);
		const state = pair.opener.getFullState();
		const toLocalScript = buildToLocalScript(
			deriveRevocationPubkey(
				state.localBasepoints.revocationBasepoint,
				revokedPoint
			),
			derivePublicKey(
				state.remoteBasepoints!.delayedPaymentBasepoint,
				revokedPoint
			),
			state.localConfig.toSelfDelay
		);
		const toLocalSpk = bitcoin.payments.p2wsh({
			redeem: { output: toLocalScript },
			network
		}).output!;
		expect(tx.outs.some((o) => o.script.equals(toLocalSpk))).to.be.true;
		// Consumed once: a second take returns null.
		expect(pair.opener.takeRevokedCommitmentTx(secret)).to.be.null;
	});

	it('fails loud when the to_local output is absent', function () {
		const { ctx } = buildRevokedContext(p2wpkhScript());
		const bogus = {
			...ctx,
			remoteDelayedBasepoint: getPublicKey(crypto.randomBytes(32))
		};
		expect(() =>
			buildJusticeBackup(bogus, {
				blobType: BlobType.ALTRUIST_COMMIT,
				sweepFeeRate: 2500n
			})
		).to.throw(/to_local output not found/);
	});

	it('excludes the lessor lease-locked to_remote from the kit (S-L.H4)', function () {
		// Blob v0 has no lease field: an LND tower rebuilds the PLAIN confirmed
		// to_remote with locktime 0 and could never spend the CLTV-locked output;
		// because the client pre-signs over the exact tx the tower assembles,
		// including it would invalidate the whole kit (to_local penalty too).
		const built = buildRevokedContext(p2wpkhScript());
		const leaseExpiry = 804032;
		// The revoked (buyer) commitment carries OUR lease-locked to_remote.
		const leaseSpk = bitcoin.payments.p2wsh({
			redeem: {
				output: buildToRemoteAnchorScript(
					built.ctx.localPaymentPubkey!,
					leaseExpiry
				)
			},
			network
		}).output!;
		const plainP2wpkh = bitcoin.payments.p2wpkh({
			pubkey: built.ctx.localPaymentPubkey!,
			network
		}).output!;
		for (const out of built.ctx.revokedTx.outs) {
			if (out.script.equals(plainP2wpkh)) out.script = leaseSpk;
		}
		const ctx = {
			...built.ctx,
			isAnchor: true,
			isLessor: true,
			leaseExpiry
		};

		const backup = buildJusticeBackup(ctx, {
			blobType: BlobType.ALTRUIST_COMMIT,
			sweepFeeRate: 2500n
		});
		const revokedTxid = Buffer.from(ctx.revokedTx.getId(), 'hex').reverse();
		const kit = decryptJusticeKitV0(
			backup.encryptedBlob,
			breachKeyFromTxid(revokedTxid)
		);
		// The kit stands on the to_local penalty alone; no to_remote rides along.
		expect(kit.commitToRemotePubKey).to.be.undefined;
		expect(kit.commitToLocalSig).to.have.length(64);
		expect(Number(backup.sweptSats)).to.be.greaterThan(0);
		expect(Number(backup.sweptSats)).to.be.lessThan(built.toLocalValue);
	});

	it('names the blob limitation for a lessee-side lease-locked to_local (S-L.H4)', function () {
		const built = buildRevokedContext(p2wpkhScript());
		const leaseExpiry = 804032;
		// We are the LESSEE: the peer (lessor) commitment's to_local carries the
		// lease CLTV. Rebuild the revoked tx's to_local as the lease variant.
		const plainToLocalSpk = bitcoin.payments.p2wsh({
			redeem: {
				output: buildToLocalScript(
					built.revocationPubkey,
					built.theirDelayed,
					built.toSelfDelay
				)
			},
			network
		}).output!;
		const leaseToLocalSpk = bitcoin.payments.p2wsh({
			redeem: {
				output: buildToLocalScript(
					built.revocationPubkey,
					built.theirDelayed,
					built.toSelfDelay,
					leaseExpiry
				)
			},
			network
		}).output!;
		for (const out of built.ctx.revokedTx.outs) {
			if (out.script.equals(plainToLocalSpk)) out.script = leaseToLocalSpk;
		}
		const ctx = { ...built.ctx, isAnchor: true, leaseExpiry };
		expect(() =>
			buildJusticeBackup(ctx, {
				blobType: BlobType.ALTRUIST_COMMIT,
				sweepFeeRate: 2500n
			})
		).to.throw(/lease-locked to_local/);
	});
});

/** In-process fake tower: decodes wtwire and replies per configured behaviour. */
class FakeTower extends EventEmitter implements ITowerTransport {
	connected = false;
	created = false;
	receivedUpdates: Array<{ seqNum: number; hint: Buffer }> = [];
	lastApplied = 0;
	behaviour: {
		createCode?: number;
		updateCode?: (seqNum: number) => number;
		clientBehindTo?: number;
	} = {};

	constructor(public addr: ITowerAddress) {
		super();
	}

	isConnected(): boolean {
		return this.connected;
	}

	async connect(): Promise<void> {
		this.connected = true;
	}

	close(): void {
		if (!this.connected) return;
		this.connected = false;
		this.emit('close');
	}

	send(type: number, payload: Buffer): void {
		setImmediate(() => {
			if (!this.connected) return;
			if (type === WtMessageType.INIT) {
				decodeInit(payload);
				this.reply(
					WtMessageType.INIT,
					encodeInit({
						connFeatures: Buffer.from([0x02]),
						chainHash: chainHashForNetwork(network)
					})
				);
			} else if (type === WtMessageType.CREATE_SESSION) {
				decodeCreateSession(payload);
				this.created = true;
				this.reply(
					WtMessageType.CREATE_SESSION_REPLY,
					encodeCreateSessionReply({
						code: this.behaviour.createCode ?? CreateSessionCode.OK,
						lastApplied: 0,
						data: Buffer.alloc(0)
					})
				);
			} else if (type === WtMessageType.STATE_UPDATE) {
				const upd = decodeStateUpdate(payload);
				const code = this.behaviour.updateCode
					? this.behaviour.updateCode(upd.seqNum)
					: StateUpdateCode.OK;
				if (code === StateUpdateCode.OK) {
					this.receivedUpdates.push({ seqNum: upd.seqNum, hint: upd.hint });
					this.lastApplied = upd.seqNum;
				}
				this.reply(
					WtMessageType.STATE_UPDATE_REPLY,
					encodeStateUpdateReply({
						code,
						lastApplied:
							code === StateUpdateCode.CLIENT_BEHIND
								? this.behaviour.clientBehindTo ?? 0
								: this.lastApplied
					})
				);
			}
		});
	}

	private reply(type: number, payload: Buffer): void {
		this.emit('message', type, payload);
	}
}

function tick(ms = 5): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}

/** In-memory IWatchtowerStore for deterministic backlog-drain tests. */
class InMemoryStore implements IWatchtowerStore {
	sessions: Array<{ session: IWatchtowerSession; sessionKey: Buffer }> = [];
	updates: Array<IWatchtowerUpdate & { id: number }> = [];
	private nextId = 1;

	saveWatchtowerSession(session: IWatchtowerSession, sessionKey: Buffer): void {
		this.sessions = this.sessions.filter(
			(s) => s.session.sessionId !== session.sessionId
		);
		this.sessions.push({ session, sessionKey });
	}
	loadWatchtowerSessions(): Array<IWatchtowerSession & { sessionKey: Buffer }> {
		return this.sessions.map((s) => ({
			...s.session,
			sessionKey: s.sessionKey
		}));
	}
	setWatchtowerSessionProgress(
		sessionId: string,
		seqNum: number,
		lastApplied: number
	): void {
		const s = this.sessions.find((x) => x.session.sessionId === sessionId);
		if (s) {
			s.session.seqNum = seqNum;
			s.session.lastApplied = lastApplied;
		}
	}
	deleteWatchtowerTower(towerUri: string): void {
		this.sessions = this.sessions.filter(
			(s) => s.session.towerUri !== towerUri
		);
		this.updates = this.updates.filter((u) => u.towerUri !== towerUri);
	}
	addWatchtowerUpdate(update: IWatchtowerUpdate): number {
		const id = this.nextId++;
		this.updates.push({ ...update, id });
		return id;
	}
	loadPendingWatchtowerUpdates(): Array<IWatchtowerUpdate & { id: number }> {
		return this.updates.filter((u) => !u.acked);
	}
	markWatchtowerUpdateAcked(id: number, seqNum: number): void {
		const u = this.updates.find((x) => x.id === id);
		if (u) {
			u.acked = true;
			u.seqNum = seqNum;
		}
	}
}

const TOWER_URI =
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798@127.0.0.1:9911';

function contextForClient(): IJusticeContext {
	return buildRevokedContext(p2wpkhScript()).ctx;
}

describe('watchtower client session state machine (fake tower)', function () {
	function makeClient(
		fake: FakeTower,
		store?: IWatchtowerStore
	): WatchtowerClient {
		return new WatchtowerClient({
			localPrivateKey: crypto.randomBytes(32),
			chainHash: chainHashForNetwork(network),
			network,
			towers: [TOWER_URI],
			store,
			transportFactory: (): ITowerTransport => fake
		});
	}

	it('negotiates a session and ships an acked update', async function () {
		const fake = new FakeTower(parseTowerUri(TOWER_URI));
		const client = makeClient(fake);
		await client.start();
		await tick();
		expect(fake.created).to.be.true;

		client.backupRevokedState(contextForClient());
		await tick(20);

		expect(fake.receivedUpdates.length).to.equal(1);
		expect(fake.receivedUpdates[0].seqNum).to.equal(1);
		const health = client.getHealth();
		expect(health[0].sessions).to.equal(1);
		expect(health[0].pendingBacklog).to.equal(0);
		client.stop();
	});

	it('re-negotiates a fresh session when the tower rejects (nack)', async function () {
		const fake = new FakeTower(parseTowerUri(TOWER_URI));
		fake.behaviour.updateCode = (): number =>
			StateUpdateCode.MAX_UPDATES_EXCEEDED;
		const client = makeClient(fake);
		await client.start();
		await tick();
		client.backupRevokedState(contextForClient());
		await tick(20);
		// Update stays queued (never dropped) and the exhausted session is cleared.
		expect(fake.receivedUpdates.length).to.equal(0);
		expect(client.getHealth()[0].pendingBacklog).to.equal(1);
		client.stop();
	});

	it('drains a persisted backlog on (re)connect', async function () {
		// A prior session + an un-acked update survive a restart in the store; a
		// fresh client connects and drains the backlog without re-negotiating.
		const store = new InMemoryStore();
		store.sessions.push({
			session: {
				towerUri: TOWER_URI,
				towerPubkey: parseTowerUri(TOWER_URI).pubkey,
				sessionId: getPublicKey(crypto.randomBytes(32)).toString('hex'),
				blobType: BlobType.ALTRUIST_COMMIT,
				maxUpdates: 1024,
				sweepFeeRate: '2500',
				seqNum: 0,
				lastApplied: 0,
				createdAt: Date.now()
			},
			sessionKey: crypto.randomBytes(32)
		});
		store.updates.push({
			id: 1,
			towerUri: TOWER_URI,
			channelId: 'c1',
			blobType: BlobType.ALTRUIST_COMMIT,
			hint: crypto.randomBytes(16).toString('hex'),
			encryptedBlob: crypto.randomBytes(314).toString('hex'),
			seqNum: 0,
			acked: false,
			createdAt: Date.now()
		});

		const fake = new FakeTower(parseTowerUri(TOWER_URI));
		const client = makeClient(fake, store);
		await client.start();
		await tick(20);

		expect(fake.created, 'no new session negotiated').to.be.false;
		expect(fake.receivedUpdates.length).to.equal(1);
		expect(store.updates[0].acked).to.be.true;
		expect(client.getHealth()[0].pendingBacklog).to.equal(0);
		client.stop();
	});
});

describe('watchtower persistence round-trip', function () {
	it('persists and reloads sessions + pending updates', function () {
		const store = new SqliteStorage(':memory:');
		store.open();
		const session: IWatchtowerSession = {
			towerUri: TOWER_URI,
			towerPubkey: parseTowerUri(TOWER_URI).pubkey,
			sessionId: getPublicKey(crypto.randomBytes(32)).toString('hex'),
			blobType: BlobType.ALTRUIST_COMMIT,
			maxUpdates: 1024,
			sweepFeeRate: '2500',
			seqNum: 0,
			lastApplied: 0,
			createdAt: Date.now()
		};
		const sessionKey = crypto.randomBytes(32);
		store.saveWatchtowerSession(session, sessionKey);
		const loaded = store.loadWatchtowerSessions();
		expect(loaded.length).to.equal(1);
		expect(loaded[0].sessionKey).to.deep.equal(sessionKey);
		expect(loaded[0].sessionId).to.equal(session.sessionId);

		const update: IWatchtowerUpdate = {
			towerUri: TOWER_URI,
			channelId: 'c1',
			blobType: BlobType.ALTRUIST_COMMIT,
			hint: crypto.randomBytes(16).toString('hex'),
			encryptedBlob: crypto.randomBytes(314).toString('hex'),
			seqNum: 0,
			acked: false,
			createdAt: Date.now()
		};
		const id = store.addWatchtowerUpdate(update);
		let pending = store.loadPendingWatchtowerUpdates();
		expect(pending.length).to.equal(1);
		expect(pending[0].encryptedBlob).to.equal(update.encryptedBlob);

		store.markWatchtowerUpdateAcked(id, 1);
		pending = store.loadPendingWatchtowerUpdates();
		expect(pending.length).to.equal(0);

		store.setWatchtowerSessionProgress(session.sessionId, 5, 4);
		expect(store.loadWatchtowerSessions()[0].seqNum).to.equal(5);

		store.deleteWatchtowerTower(TOWER_URI);
		expect(store.loadWatchtowerSessions().length).to.equal(0);
		store.close();
	});

	it('encrypts session key + blob at rest when a key is set', function () {
		const encKey = crypto.randomBytes(32);
		const store = new SqliteStorage(':memory:', undefined, {
			encryptionKey: encKey
		});
		store.open();
		const session: IWatchtowerSession = {
			towerUri: TOWER_URI,
			towerPubkey: parseTowerUri(TOWER_URI).pubkey,
			sessionId: getPublicKey(crypto.randomBytes(32)).toString('hex'),
			blobType: BlobType.ALTRUIST_COMMIT,
			maxUpdates: 1024,
			sweepFeeRate: '2500',
			seqNum: 0,
			lastApplied: 0,
			createdAt: Date.now()
		};
		const sessionKey = crypto.randomBytes(32);
		store.saveWatchtowerSession(session, sessionKey);
		// Raw column must not contain the plaintext base64 key.
		const raw = (store as any).db
			.prepare('SELECT session_key FROM watchtower_sessions')
			.get() as { session_key: string };
		expect(raw.session_key.startsWith('enc1:')).to.be.true;
		expect(store.loadWatchtowerSessions()[0].sessionKey).to.deep.equal(
			sessionKey
		);
		store.close();
	});
});

describe('watchtower config gating', function () {
	it('is disabled and inert with no towers configured', function () {
		const client = new WatchtowerClient({
			localPrivateKey: crypto.randomBytes(32),
			chainHash: chainHashForNetwork(network),
			network,
			towers: []
		});
		expect(client.enabled).to.be.false;
		// backupRevokedState must be a no-op (no towers, no throw).
		client.backupRevokedState(contextForClient());
		expect(client.getHealth()).to.deep.equal([]);
	});
});

describe('watchtower chain hashes', function () {
	it('match the channel-layer chain hash constants (internal byte order)', function () {
		// Regression: the regtest entry was stored in display byte order and a
		// live LND tower rejected Init with "remote init has unknown chain
		// hash". The channel layer's constants are interop-proven; the wtwire
		// Init chain_hash must be byte-identical to them.
		expect(
			chainHashForNetwork(bitcoin.networks.bitcoin).equals(BITCOIN_CHAIN_HASH)
		).to.equal(true);
		expect(
			chainHashForNetwork(bitcoin.networks.regtest).equals(REGTEST_CHAIN_HASH)
		).to.equal(true);
	});

	it('regtest chain hash is the genesis hash in internal byte order', function () {
		// bitcoin-cli -regtest getblockhash 0 (display order), reversed.
		const display =
			'0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206';
		const internal = Buffer.from(display, 'hex').reverse();
		expect(
			chainHashForNetwork(bitcoin.networks.regtest).equals(internal)
		).to.equal(true);
	});
});
