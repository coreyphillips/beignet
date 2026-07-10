/**
 * Watchtower coverage deferred from the original client PR: anchor-channel
 * to_remote sweeps in the v0 kit and the version-1 (taproot) justice kit.
 *
 * The v1 layout and the tower-side justice reconstruction are pinned against
 * lnd master/v0.20 source (watchtower/blob/justice_kit_packet.go,
 * justice_kit.go, commitments.go, lookout/justice_descriptor.go):
 *   - v1 plaintext (300 bytes): addrLen(1) | paddedSweepAddr(42) |
 *     revocationPubKey x-only(32) | localDelayPubKey x-only(32) |
 *     commitToLocalSig schnorr(64) | delayScriptHash(32) |
 *     commitToRemotePubKey compressed(33, maybe blank) |
 *     commitToRemoteSig schnorr(64, maybe blank)
 *   - anchor to_remote: 1-CSV P2WSH (CommitScriptToRemoteConfirmed), input
 *     sequence 1, witness weight 113; anchor to_local penalty weight 157.
 *   - taproot: to_local revoke-leaf script-path (weight 202), to_remote
 *     settle-leaf script-path with sequence 1 (weight 139), SIGHASH_DEFAULT.
 *
 * The tower-side justice transactions in these tests are reassembled from the
 * DECRYPTED KIT + revoked tx + policy only (lnd semantics), never from
 * beignet's own builder, so a divergence in scripts, sequences, weights or fee
 * math fails signature verification here instead of on a live tower.
 */
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
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
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
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	buildTaprootToLocalRevokeScript,
	buildTaprootToRemoteScript,
	TAPROOT_NUMS_KEY,
	toXOnly
} from '../../src/lightning/script/commitment-taproot';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
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
	decodeInit,
	encodeInit,
	decodeCreateSession,
	encodeCreateSessionReply,
	decodeStateUpdate,
	encodeStateUpdateReply
} from '../../src/lightning/watchtower/wtwire';
import {
	BlobType,
	V1_PLAINTEXT_SIZE,
	NONCE_SIZE,
	CIPHERTEXT_EXPANSION,
	IJusticeKitV1,
	encodeJusticeKitV1,
	decodeJusticeKitV1,
	encryptJusticeKitV1,
	decryptJusticeKitV1,
	decryptJusticeKitV0,
	breachHintFromTxid,
	breachKeyFromTxid
} from '../../src/lightning/watchtower/blob';
import {
	buildJusticeBackup,
	blobTypeForChannel,
	IJusticeContext
} from '../../src/lightning/watchtower/justice';
import { WatchtowerClient } from '../../src/lightning/watchtower/watchtower-client';
import { parseTowerUri } from '../../src/lightning/watchtower/tower-connection';
import {
	ITowerAddress,
	ITowerTransport
} from '../../src/lightning/watchtower/types';
import { chainHashForNetwork } from '../../src/lightning/watchtower';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;

// lnd input/size.go constants (mirrored INDEPENDENTLY of src/ for the
// tower-side reassembly below).
const TO_LOCAL_PENALTY_WITNESS = 157;
const TO_REMOTE_CONFIRMED_WITNESS = 113;
const TAPROOT_TO_LOCAL_REVOKE_WITNESS = 202;
const TAPROOT_TO_REMOTE_WITNESS = 139;

function det(tag: string): Buffer {
	return crypto.createHash('sha256').update(tag).digest();
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(a: any) =>
			a.type === ChannelActionType.SEND_MESSAGE && a.messageType === msgType
	);
}

/** One commitment round; returns the secret the acceptor revealed. */
function exchangeOnce(
	opener: Channel,
	acceptor: Channel,
	taprootPartial = false
): Buffer {
	const csActions = opener.signCommitment(
		crypto.randomBytes(64),
		[],
		taprootPartial ? crypto.randomBytes(98) : undefined
	);
	const csMsg = findSendAction(csActions, MessageType.COMMITMENT_SIGNED);
	const raaActions = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(csMsg.payload)
	);
	const raaMsg = findSendAction(raaActions, MessageType.REVOKE_AND_ACK);
	const raa = decodeRevokeAndAckMessage(raaMsg.payload);
	opener.handleRevokeAndAck(raa);
	return raa.perCommitmentSecret;
}

function freshPair(seedTag: string): {
	opener: Channel;
	acceptor: Channel;
	openerPrivkeys: Buffer[];
} {
	const { basepoints: openerBp, privkeys: openerPrivkeys } = makeBasepoints(
		det(`${seedTag}-opener`)
	);
	const { basepoints: acceptorBp } = makeBasepoints(det(`${seedTag}-acceptor`));
	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xcc),
			fundingSatoshis: 1_000_000n,
			pushMsat: 200_000_000n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBp,
			localPerCommitmentSeed: det(`${seedTag}-opener-commit`)
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: Buffer.alloc(32, 0xcc),
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBp,
			localPerCommitmentSeed: det(`${seedTag}-acceptor-commit`),
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
			det(`${seedTag}-funding`),
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

function channelTypeOf(...features: Feature[]): Buffer {
	const flags = FeatureFlags.empty();
	for (const f of features) flags.setCompulsory(f);
	return flags.toBuffer();
}

/**
 * Drive a real channel through one revocation, flip the negotiated
 * channel_type, and rebuild the acceptor's revoked commitment in that format
 * (the chain-monitor fixture pattern). Returns the justice context.
 */
function buildRevokedContextFor(
	kind: 'anchor' | 'taproot',
	sweepScript: Buffer,
	seedTag: string
): { ctx: IJusticeContext; revokedTx: bitcoin.Transaction } {
	const pair = freshPair(seedTag);
	exchangeOnce(pair.opener, pair.acceptor);
	const state = pair.opener.getFullState();
	state.channelType =
		kind === 'anchor'
			? channelTypeOf(Feature.STATIC_REMOTE_KEY, Feature.ANCHOR_ZERO_FEE_HTLC)
			: channelTypeOf(Feature.OPTION_TAPROOT);

	const secret = state.shaChainStore.getSecret(MAX_INDEX - 0n);
	expect(secret, 'revoked secret present').to.not.be.null;
	const revokedPoint = perCommitmentPointFromSecret(secret!);
	const built = buildRemoteCommitment(state, revokedPoint, 0n);
	const revokedTx = built.result.tx;

	const ctx: IJusticeContext = {
		channelId: `wt-${kind}`,
		revokedTx,
		perCommitmentSecret: secret!,
		revocationBasepoint: state.localBasepoints.revocationBasepoint,
		revocationBasepointSecret: pair.openerPrivkeys[1],
		remoteDelayedBasepoint: state.remoteBasepoints!.delayedPaymentBasepoint,
		toSelfDelay: state.localConfig.toSelfDelay,
		isAnchor: true,
		isTaproot: kind === 'taproot',
		localPaymentPubkey: state.localBasepoints.paymentBasepoint,
		paymentBasepointSecret: pair.openerPrivkeys[2],
		sweepScript,
		network
	};
	return { ctx, revokedTx };
}

function p2wpkhScript(seed: string): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(det(seed)),
		network
	}).output!;
}

/** lnd TxWeightEstimator for a justice tx (inputs 41 vbytes, 1 sweep output). */
function justiceWeight(
	numInputs: number,
	sweepLen: number,
	witness: number
): number {
	const stripped = 8 + 1 + numInputs * 41 + 1 + (sweepLen === 22 ? 31 : 43);
	return stripped * 4 + 2 + witness;
}

const TAG_TAPBRANCH = crypto.createHash('sha256').update('TapBranch').digest();

function tapBranch(a: Buffer, b: Buffer): Buffer {
	const [l, r] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
	return crypto
		.createHash('sha256')
		.update(Buffer.concat([TAG_TAPBRANCH, TAG_TAPBRANCH, l, r]))
		.digest();
}

const TAG_TAPTWEAK = crypto.createHash('sha256').update('TapTweak').digest();

/** BIP341 output key from an internal x-only key + merkle root. */
function taprootOutputKey(internalXOnly: Buffer, merkleRoot: Buffer): Buffer {
	const tweak = crypto
		.createHash('sha256')
		.update(
			Buffer.concat([TAG_TAPTWEAK, TAG_TAPTWEAK, internalXOnly, merkleRoot])
		)
		.digest();
	const tweaked = ecc.xOnlyPointAddTweak(internalXOnly, tweak);
	expect(tweaked, 'valid taproot tweak').to.not.be.null;
	return Buffer.from(tweaked!.xOnlyPubkey);
}

describe('watchtower v1 (taproot) justice kit codec', function () {
	function fixedKitV1(withRemote: boolean): IJusticeKitV1 {
		const kit: IJusticeKitV1 = {
			sweepAddress: p2wpkhScript('v1-sweep'),
			revocationPubKey: toXOnly(getPublicKey(det('v1-rev'))),
			localDelayPubKey: toXOnly(getPublicKey(det('v1-delay'))),
			commitToLocalSig:
				det('v1-siglocal-a').subarray(0, 32).length === 32
					? Buffer.concat([det('v1-siglocal-a'), det('v1-siglocal-b')])
					: Buffer.alloc(64),
			delayScriptHash: det('v1-delayhash')
		};
		if (withRemote) {
			kit.commitToRemotePubKey = getPublicKey(det('v1-remote'));
			kit.commitToRemoteSig = Buffer.concat([
				det('v1-sigremote-a'),
				det('v1-sigremote-b')
			]);
		}
		return kit;
	}

	it('encodes the exact 300-byte lnd v1 plaintext layout', function () {
		const kit = fixedKitV1(true);
		// Expected bytes assembled independently at the lnd-documented offsets:
		// addrLen | paddedAddr(42) | rev(32) | delay(32) | sigLocal(64) |
		// delayScriptHash(32) | remotePub(33) | sigRemote(64).
		const paddedAddr = Buffer.alloc(42);
		kit.sweepAddress.copy(paddedAddr);
		const expected = Buffer.concat([
			Buffer.from([kit.sweepAddress.length]),
			paddedAddr,
			kit.revocationPubKey,
			kit.localDelayPubKey,
			kit.commitToLocalSig,
			kit.delayScriptHash,
			kit.commitToRemotePubKey!,
			kit.commitToRemoteSig!
		]);
		expect(expected.length).to.equal(V1_PLAINTEXT_SIZE);
		const pt = encodeJusticeKitV1(kit);
		expect(pt.length).to.equal(V1_PLAINTEXT_SIZE);
		expect(pt.equals(expected), 'byte-exact v1 plaintext').to.equal(true);
		expect(decodeJusticeKitV1(pt)).to.deep.equal(kit);
	});

	it('pads a missing to-remote with zero bytes and drops it on decode', function () {
		const kit = fixedKitV1(false);
		const pt = encodeJusticeKitV1(kit);
		expect(pt.length).to.equal(V1_PLAINTEXT_SIZE);
		// Bytes 203..300 (remote pubkey + sig) must be blank.
		expect(pt.subarray(203).equals(Buffer.alloc(97))).to.equal(true);
		const decoded = decodeJusticeKitV1(pt);
		expect(decoded.commitToRemotePubKey).to.equal(undefined);
		expect(decoded.commitToRemoteSig).to.equal(undefined);
	});

	it('encrypts to the lnd envelope (nonce || ct || mac) and round-trips', function () {
		const kit = fixedKitV1(true);
		const key = breachKeyFromTxid(det('v1-txid'));
		const blob = encryptJusticeKitV1(kit, key);
		// blob.Size(v1 kit) = 24 + 300 + 16 = 340.
		expect(blob.length).to.equal(
			NONCE_SIZE + V1_PLAINTEXT_SIZE + CIPHERTEXT_EXPANSION
		);
		expect(decryptJusticeKitV1(blob, key)).to.deep.equal(kit);
		expect(() =>
			decryptJusticeKitV1(blob, breachKeyFromTxid(det('other-txid')))
		).to.throw();
	});

	it('selects blob types like lnd blob.TypeFromChannel (taproot first)', function () {
		expect(blobTypeForChannel(false, false)).to.equal(BlobType.ALTRUIST_COMMIT);
		expect(blobTypeForChannel(true, false)).to.equal(
			BlobType.ALTRUIST_ANCHOR_COMMIT
		);
		// Taproot channel_types imply anchors elsewhere in beignet, so the
		// taproot flag must win even when isAnchor is also true.
		expect(blobTypeForChannel(true, true)).to.equal(
			BlobType.ALTRUIST_TAPROOT_COMMIT
		);
	});
});

describe('watchtower anchor to_remote against a REAL revoked commitment', function () {
	it('packs the 1-CSV P2WSH to_remote and both sigs verify on the tower-built tx', function () {
		const sweepScript = p2wpkhScript('anchor-sweep');
		const { ctx, revokedTx } = buildRevokedContextFor(
			'anchor',
			sweepScript,
			'wt-anchor'
		);
		const backup = buildJusticeBackup(ctx, {
			blobType: BlobType.ALTRUIST_ANCHOR_COMMIT,
			sweepFeeRate: 2500n
		});
		const revokedTxid = Buffer.from(revokedTx.getId(), 'hex').reverse();
		expect(backup.hint).to.deep.equal(breachHintFromTxid(revokedTxid));
		const kit = decryptJusticeKitV0(
			backup.encryptedBlob,
			breachKeyFromTxid(revokedTxid)
		);

		// The tower rebuilds both scripts FROM THE KIT ALONE and locates the
		// outputs on the breach tx (anchorJusticeKit.To{Local,Remote}OutputSpendInfo).
		const toLocalScript = buildToLocalScript(
			kit.revocationPubKey,
			kit.localDelayPubKey,
			kit.csvDelay
		);
		const toLocalSpk = bitcoin.payments.p2wsh({
			redeem: { output: toLocalScript },
			network
		}).output!;
		expect(
			kit.commitToRemotePubKey,
			'anchor to_remote pubkey packed'
		).to.not.equal(undefined);
		expect(kit.commitToRemotePubKey).to.deep.equal(ctx.localPaymentPubkey);
		const toRemoteScript = buildToRemoteAnchorScript(kit.commitToRemotePubKey!);
		const toRemoteSpk = bitcoin.payments.p2wsh({
			redeem: { output: toRemoteScript },
			network
		}).output!;
		const toLocalIdx = revokedTx.outs.findIndex((o) =>
			o.script.equals(toLocalSpk)
		);
		const toRemoteIdx = revokedTx.outs.findIndex((o) =>
			o.script.equals(toRemoteSpk)
		);
		expect(toLocalIdx, 'to_local located').to.be.gte(0);
		expect(toRemoteIdx, 'anchor P2WSH to_remote located').to.be.gte(0);

		// Reassemble the justice tx exactly as lnd's lookout would: BIP69 input
		// order, to_local sequence 0, anchor to_remote sequence 1, witness
		// weights 157 + 113, fee = rate * weight / 1000, one sweep output.
		const weight = justiceWeight(
			2,
			sweepScript.length,
			TO_LOCAL_PENALTY_WITNESS + TO_REMOTE_CONFIRMED_WITNESS
		);
		const fee = (2500n * BigInt(weight)) / 1000n;
		const total =
			BigInt(revokedTx.outs[toLocalIdx].value) +
			BigInt(revokedTx.outs[toRemoteIdx].value);
		const jtx = new bitcoin.Transaction();
		jtx.version = 2;
		const ordered = [
			{ idx: toLocalIdx, seq: 0 },
			{ idx: toRemoteIdx, seq: 1 }
		].sort((a, b) => a.idx - b.idx);
		for (const inp of ordered) {
			jtx.addInput(revokedTxid, inp.idx, inp.seq);
		}
		jtx.addOutput(sweepScript, Number(total - fee));
		expect(backup.sweptSats).to.equal(total - fee);

		// Verify the blob's pre-signed SIGHASH_ALL signatures against the
		// tower-reconstructed transaction (input sequences are committed via
		// hashSequence, so a wrong sequence would fail here).
		for (let i = 0; i < ordered.length; i++) {
			const isLocal = ordered[i].idx === toLocalIdx;
			const sighash = jtx.hashForWitnessV0(
				i,
				isLocal ? toLocalScript : toRemoteScript,
				revokedTx.outs[ordered[i].idx].value,
				bitcoin.Transaction.SIGHASH_ALL
			);
			const pub = isLocal ? kit.revocationPubKey : kit.commitToRemotePubKey!;
			const sig = isLocal ? kit.commitToLocalSig : kit.commitToRemoteSig!;
			expect(
				ecc.verify(sighash, pub, sig),
				`${isLocal ? 'to_local' : 'to_remote'} signature valid`
			).to.equal(true);
		}

		// Witness templates the tower assembles (anchorJusticeKit):
		//   to_local:  [<sig|ALL>, 0x01, toLocalScript]
		//   to_remote: [<sig|ALL>, toRemoteScript]  (sequence 1)
		// Assert the scripts end with the expected opcodes so the templates
		// reconstruct: <pub> OP_CHECKSIGVERIFY OP_1 OP_CHECKSEQUENCEVERIFY.
		expect(toRemoteScript[0]).to.equal(33); // push 33-byte pubkey
		expect(toRemoteScript.subarray(34).toString('hex')).to.equal('ad51b2'); // CSV form
	});

	it('legacy channels still pack the p2wpkh to_remote with sequence 0 weights', function () {
		// Regression guard: the anchor branch must not disturb legacy justice.
		const sweepScript = p2wpkhScript('legacy-sweep');
		const pair = freshPair('wt-legacy-guard');
		exchangeOnce(pair.opener, pair.acceptor);
		const state = pair.opener.getFullState();
		const secret = state.shaChainStore.getSecret(MAX_INDEX - 0n)!;
		const revokedTx = buildRemoteCommitment(
			state,
			perCommitmentPointFromSecret(secret),
			0n
		).result.tx;
		const ctx: IJusticeContext = {
			channelId: 'wt-legacy-guard',
			revokedTx,
			perCommitmentSecret: secret,
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
		const backup = buildJusticeBackup(ctx, {
			blobType: BlobType.ALTRUIST_COMMIT,
			sweepFeeRate: 2500n
		});
		const revokedTxid = Buffer.from(revokedTx.getId(), 'hex').reverse();
		const kit = decryptJusticeKitV0(
			backup.encryptedBlob,
			breachKeyFromTxid(revokedTxid)
		);
		expect(kit.commitToRemotePubKey).to.deep.equal(ctx.localPaymentPubkey);
		// p2wpkh to_remote present on the revoked tx.
		const spk = bitcoin.payments.p2wpkh({
			pubkey: kit.commitToRemotePubKey!,
			network
		}).output!;
		expect(revokedTx.outs.some((o) => o.script.equals(spk))).to.equal(true);
	});
});

describe('watchtower v1 kit against a REAL revoked taproot commitment', function () {
	it('decrypted kit rebuilds the taproot justice spend byte-for-byte', function () {
		const sweepScript = p2wpkhScript('taproot-sweep');
		const { ctx, revokedTx } = buildRevokedContextFor(
			'taproot',
			sweepScript,
			'wt-taproot'
		);
		const backup = buildJusticeBackup(ctx, {
			blobType: BlobType.ALTRUIST_TAPROOT_COMMIT,
			sweepFeeRate: 2500n
		});
		const revokedTxid = Buffer.from(revokedTx.getId(), 'hex').reverse();
		expect(backup.hint).to.deep.equal(breachHintFromTxid(revokedTxid));
		const kit = decryptJusticeKitV1(
			backup.encryptedBlob,
			breachKeyFromTxid(revokedTxid)
		);

		// Kit fields must equal what the chain monitor independently derives for
		// this revoked state.
		const point = perCommitmentPointFromSecret(ctx.perCommitmentSecret);
		const revocationPubkey = deriveRevocationPubkey(
			ctx.revocationBasepoint,
			point
		);
		const theirDelayed = derivePublicKey(ctx.remoteDelayedBasepoint, point);
		expect(kit.revocationPubKey).to.deep.equal(toXOnly(revocationPubkey));
		expect(kit.localDelayPubKey).to.deep.equal(toXOnly(theirDelayed));
		const monitorToLocal = buildTaprootToLocalOutput(
			revocationPubkey,
			theirDelayed,
			ctx.toSelfDelay,
			network
		);
		expect(kit.delayScriptHash).to.deep.equal(
			tapleafHash(monitorToLocal.delay.script)
		);
		expect(kit.sweepAddress).to.deep.equal(sweepScript);
		expect(kit.commitToRemotePubKey).to.deep.equal(ctx.localPaymentPubkey);

		// Tower-side reconstruction from the KIT ALONE (taprootJusticeKit):
		// revoke leaf from the two x-only keys, root = tapBranch(revokeLeafHash,
		// delayScriptHash), output key = NUMS tweaked by the root.
		const revokeScript = buildTaprootToLocalRevokeScript(
			kit.revocationPubKey,
			kit.localDelayPubKey
		);
		const toLocalRoot = tapBranch(
			tapleafHash(revokeScript),
			kit.delayScriptHash
		);
		const toLocalKey = taprootOutputKey(TAPROOT_NUMS_KEY, toLocalRoot);
		const toLocalSpk = Buffer.concat([Buffer.from([0x51, 0x20]), toLocalKey]);
		const toLocalIdx = revokedTx.outs.findIndex((o) =>
			o.script.equals(toLocalSpk)
		);
		expect(toLocalIdx, 'taproot to_local located from kit').to.be.gte(0);
		expect(toLocalSpk).to.deep.equal(monitorToLocal.output);

		// to_remote: single settle leaf keyed by the kit's compressed pubkey.
		const settleScript = buildTaprootToRemoteScript(kit.commitToRemotePubKey!);
		const toRemoteKey = taprootOutputKey(
			TAPROOT_NUMS_KEY,
			tapleafHash(settleScript)
		);
		const toRemoteSpk = Buffer.concat([Buffer.from([0x51, 0x20]), toRemoteKey]);
		const toRemoteIdx = revokedTx.outs.findIndex((o) =>
			o.script.equals(toRemoteSpk)
		);
		expect(toRemoteIdx, 'taproot to_remote located from kit').to.be.gte(0);
		expect(toRemoteSpk).to.deep.equal(
			buildTaprootToRemoteOutput(kit.commitToRemotePubKey!, network).output
		);

		// Assemble the justice tx as the tower will: sequences 0 / 1, taproot
		// witness weights 202 + 139, fee floor, single sweep output.
		const weight = justiceWeight(
			2,
			sweepScript.length,
			TAPROOT_TO_LOCAL_REVOKE_WITNESS + TAPROOT_TO_REMOTE_WITNESS
		);
		const fee = (2500n * BigInt(weight)) / 1000n;
		const total =
			BigInt(revokedTx.outs[toLocalIdx].value) +
			BigInt(revokedTx.outs[toRemoteIdx].value);
		const jtx = new bitcoin.Transaction();
		jtx.version = 2;
		const ordered = [
			{
				idx: toLocalIdx,
				seq: 0,
				leaf: revokeScript,
				key: kit.revocationPubKey
			},
			{
				idx: toRemoteIdx,
				seq: 1,
				leaf: settleScript,
				key: toXOnly(kit.commitToRemotePubKey!)
			}
		].sort((a, b) => a.idx - b.idx);
		for (const inp of ordered) {
			jtx.addInput(revokedTxid, inp.idx, inp.seq);
		}
		jtx.addOutput(sweepScript, Number(total - fee));
		expect(backup.sweptSats).to.equal(total - fee);

		// BIP341 script-path digests (SIGHASH_DEFAULT) commit to every prevout
		// script/value, both sequences and the leaf hash; the blob's schnorr
		// signatures must verify under the kit's x-only keys.
		const prevScripts = ordered.map((i) => revokedTx.outs[i.idx].script);
		const prevValues = ordered.map((i) => revokedTx.outs[i.idx].value);
		for (let i = 0; i < ordered.length; i++) {
			const sighash = jtx.hashForWitnessV1(
				i,
				prevScripts,
				prevValues,
				bitcoin.Transaction.SIGHASH_DEFAULT,
				tapleafHash(ordered[i].leaf)
			);
			const sig =
				ordered[i].idx === toLocalIdx
					? kit.commitToLocalSig
					: kit.commitToRemoteSig!;
			expect(
				ecc.verifySchnorr(sighash, ordered[i].key, sig),
				`schnorr sig ${i} valid`
			).to.equal(true);
		}
	});

	it('taproot channels cache the revoked commitment for the tower path', function () {
		const pair = freshPair('wt-taproot-cache');
		// Round 1 in legacy form so the funding-state secret is consumed.
		exchangeOnce(pair.opener, pair.acceptor);
		// Flip to taproot: from here signCommitment caches TAPROOT commitments.
		const state = pair.opener.getFullState();
		state.channelType = channelTypeOf(Feature.OPTION_TAPROOT);
		// Round 2 signs + caches the taproot commitment; round 3's revoke_and_ack
		// reveals its secret (a revocation always reveals the PREVIOUS state).
		exchangeOnce(pair.opener, pair.acceptor, true);
		const secret = exchangeOnce(pair.opener, pair.acceptor, true);

		const revokedBuf = pair.opener.takeRevokedCommitmentTx(secret);
		expect(revokedBuf, 'taproot revoked tx cached').to.not.be.null;
		const revoked = bitcoin.Transaction.fromBuffer(revokedBuf!);
		const point = perCommitmentPointFromSecret(secret);
		const toLocal = buildTaprootToLocalOutput(
			deriveRevocationPubkey(state.localBasepoints.revocationBasepoint, point),
			derivePublicKey(state.remoteBasepoints!.delayedPaymentBasepoint, point),
			state.localConfig.toSelfDelay,
			network
		);
		expect(
			revoked.outs.some((o) => o.script.equals(toLocal.output)),
			'cached tx is the TAPROOT commitment'
		).to.equal(true);
	});
});

// ── Per-blob-type sessions (fake towers, one per connection) ────────────────

const TOWER_URI =
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798@127.0.0.1:9911';

interface ISessionRecord {
	blobType: number;
	updates: Array<{ seqNum: number; hint: Buffer }>;
}

/**
 * Fake tower network mirroring lnd wtserver semantics: each CONNECTION is a
 * distinct session (keyed by its transport key), one blob type per session.
 */
class FakeTowerNet {
	connections: FakeTowerConn[] = [];
	rejectBlobTypes = new Set<number>();

	factory = (addr: ITowerAddress, transportKey?: Buffer): ITowerTransport => {
		const conn = new FakeTowerConn(
			addr,
			transportKey ?? Buffer.alloc(32),
			this
		);
		this.connections.push(conn);
		return conn;
	};

	sessionFor(blobType: number): ISessionRecord | undefined {
		for (const c of this.connections) {
			if (c.session?.blobType === blobType) return c.session;
		}
		return undefined;
	}
}

class FakeTowerConn extends EventEmitter implements ITowerTransport {
	connected = false;
	session: ISessionRecord | null = null;
	createSessionBlobTypes: number[] = [];

	constructor(
		public addr: ITowerAddress,
		public transportKey: Buffer,
		private net: FakeTowerNet
	) {
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
				const req = decodeCreateSession(payload);
				this.createSessionBlobTypes.push(req.blobType);
				if (this.net.rejectBlobTypes.has(req.blobType)) {
					this.reply(
						WtMessageType.CREATE_SESSION_REPLY,
						encodeCreateSessionReply({
							code: CreateSessionCode.REJECT_BLOB_TYPE,
							lastApplied: 0,
							data: Buffer.alloc(0)
						})
					);
					return;
				}
				this.session = { blobType: req.blobType, updates: [] };
				this.reply(
					WtMessageType.CREATE_SESSION_REPLY,
					encodeCreateSessionReply({
						code: CreateSessionCode.OK,
						lastApplied: 0,
						data: Buffer.alloc(0)
					})
				);
			} else if (type === WtMessageType.STATE_UPDATE) {
				const upd = decodeStateUpdate(payload);
				if (!this.session) return;
				this.session.updates.push({ seqNum: upd.seqNum, hint: upd.hint });
				this.reply(
					WtMessageType.STATE_UPDATE_REPLY,
					encodeStateUpdateReply({
						code: StateUpdateCode.OK,
						lastApplied: upd.seqNum
					})
				);
			}
		});
	}

	private reply(type: number, payload: Buffer): void {
		this.emit('message', type, payload);
	}
}

function tick(ms = 10): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}

describe('watchtower client per-blob-type sessions', function () {
	// Building real revoked contexts is expensive; reuse across cases.
	let taprootCtx: IJusticeContext;
	let legacyPairCtx: IJusticeContext;

	before(function () {
		taprootCtx = buildRevokedContextFor(
			'taproot',
			p2wpkhScript('client-tr-sweep'),
			'wt-client-tr'
		).ctx;
		const pair = freshPair('wt-client-legacy');
		exchangeOnce(pair.opener, pair.acceptor);
		const state = pair.opener.getFullState();
		const secret = state.shaChainStore.getSecret(MAX_INDEX - 0n)!;
		legacyPairCtx = {
			channelId: 'wt-client-legacy',
			revokedTx: buildRemoteCommitment(
				state,
				perCommitmentPointFromSecret(secret),
				0n
			).result.tx,
			perCommitmentSecret: secret,
			revocationBasepoint: state.localBasepoints.revocationBasepoint,
			revocationBasepointSecret: pair.openerPrivkeys[1],
			remoteDelayedBasepoint: state.remoteBasepoints!.delayedPaymentBasepoint,
			toSelfDelay: state.localConfig.toSelfDelay,
			isAnchor: false,
			localPaymentPubkey: state.localBasepoints.paymentBasepoint,
			paymentBasepointSecret: pair.openerPrivkeys[2],
			sweepScript: p2wpkhScript('client-legacy-sweep'),
			network
		};
	});

	function makeClient(net: FakeTowerNet): WatchtowerClient {
		return new WatchtowerClient({
			localPrivateKey: crypto.randomBytes(32),
			chainHash: chainHashForNetwork(network),
			network,
			towers: [TOWER_URI],
			transportFactory: net.factory
		});
	}

	it('runs one session per blob type over separate keyed connections', async function () {
		const net = new FakeTowerNet();
		const client = makeClient(net);
		await client.start();
		await tick();
		// Eager default: the legacy session.
		expect(net.sessionFor(BlobType.ALTRUIST_COMMIT), 'legacy session').to.exist;

		client.backupRevokedState(taprootCtx);
		client.backupRevokedState(legacyPairCtx);
		await tick(40);

		const taprootSession = net.sessionFor(BlobType.ALTRUIST_TAPROOT_COMMIT);
		const legacySession = net.sessionFor(BlobType.ALTRUIST_COMMIT);
		expect(taprootSession, 'taproot session negotiated').to.exist;
		expect(taprootSession!.updates.length).to.equal(1);
		expect(taprootSession!.updates[0].seqNum).to.equal(1);
		expect(legacySession!.updates.length).to.equal(1);
		expect(legacySession!.updates[0].seqNum).to.equal(1);

		// Separate connections with distinct transport keys (LND towers key the
		// session to the connection pubkey).
		expect(net.connections.length).to.equal(2);
		expect(
			net.connections[0].transportKey.equals(net.connections[1].transportKey)
		).to.equal(false);

		const health = client.getHealth();
		expect(health[0].sessions).to.equal(2);
		expect(health[0].pendingBacklog).to.equal(0);
		client.stop();
	});

	it('queues taproot backups without crashing when the tower rejects the blob type', async function () {
		const net = new FakeTowerNet();
		net.rejectBlobTypes.add(BlobType.ALTRUIST_TAPROOT_COMMIT);
		const client = makeClient(net);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const events: any[] = [];
		client.on('log', (e) => events.push(e));
		await client.start();
		await tick();

		client.backupRevokedState(taprootCtx);
		client.backupRevokedState(legacyPairCtx);
		await tick(40);

		// Legacy flows; taproot stays queued (never dropped, never shipped).
		expect(net.sessionFor(BlobType.ALTRUIST_COMMIT)!.updates.length).to.equal(
			1
		);
		expect(net.sessionFor(BlobType.ALTRUIST_TAPROOT_COMMIT)).to.equal(
			undefined
		);
		const rejected = events.find((e) => e.event === 'session_rejected');
		expect(rejected, 'session_rejected logged').to.exist;
		expect(rejected.blobType).to.equal(BlobType.ALTRUIST_TAPROOT_COMMIT);
		expect(rejected.code).to.equal(CreateSessionCode.REJECT_BLOB_TYPE);
		expect(client.getHealth()[0].pendingBacklog).to.equal(1);

		// A second taproot backup also queues quietly.
		client.backupRevokedState(taprootCtx);
		await tick(20);
		expect(client.getHealth()[0].pendingBacklog).to.equal(2);
		client.stop();
	});

	it('persists blob types and session key routing across restarts', function () {
		const store = new SqliteStorage(':memory:');
		store.open();
		const session = {
			towerUri: TOWER_URI,
			towerPubkey: parseTowerUri(TOWER_URI).pubkey,
			sessionId: getPublicKey(det('persist-session')).toString('hex'),
			blobType: BlobType.ALTRUIST_TAPROOT_COMMIT,
			maxUpdates: 1024,
			sweepFeeRate: '2500',
			seqNum: 3,
			lastApplied: 3,
			createdAt: Date.now(),
			dialsWithSessionKey: true
		};
		store.saveWatchtowerSession(session, det('persist-key'));
		const loaded = store.loadWatchtowerSessions();
		expect(loaded[0].blobType).to.equal(BlobType.ALTRUIST_TAPROOT_COMMIT);
		expect(loaded[0].dialsWithSessionKey).to.equal(true);

		store.addWatchtowerUpdate({
			towerUri: TOWER_URI,
			channelId: 'c-tr',
			blobType: BlobType.ALTRUIST_TAPROOT_COMMIT,
			hint: det('u-hint').subarray(0, 16).toString('hex'),
			encryptedBlob: det('u-blob').toString('hex'),
			seqNum: 0,
			acked: false,
			createdAt: Date.now()
		});
		const pending = store.loadPendingWatchtowerUpdates();
		expect(pending[0].blobType).to.equal(BlobType.ALTRUIST_TAPROOT_COMMIT);

		// Rows written by pre-upgrade clients (no blob_type column value) load
		// as ALTRUIST_COMMIT, the only type old clients ever negotiated.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(store as any).db
			.prepare(
				`INSERT INTO watchtower_updates
					(tower_uri, channel_id, hint, encrypted_blob, seq_num, acked, created_at)
				 VALUES (?, ?, ?, ?, ?, 0, ?)`
			)
			.run(TOWER_URI, 'c-old', 'aa'.repeat(16), 'bb'.repeat(32), 0, Date.now());
		const all = store.loadPendingWatchtowerUpdates();
		const old = all.find((u) => u.channelId === 'c-old');
		expect(old!.blobType).to.equal(BlobType.ALTRUIST_COMMIT);
		store.close();
	});
});
