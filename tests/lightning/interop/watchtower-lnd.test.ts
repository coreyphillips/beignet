/**
 * Live interop: beignet watchtower client against a REAL LND altruist tower
 * (wtwire over Noise/Brontide).
 *
 * Requires the docker stack with the watchtower server enabled on lnd
 * (docker/docker-compose.yml maps 9911 and passes --watchtower.active):
 *   cd docker && docker compose up -d
 * Run:
 *   npx mocha --exit --timeout 120000 -r ts-node/register \
 *     tests/lightning/interop/watchtower-lnd.test.ts
 *
 * Coverage: transport handshake with LND's tower identity key, Init feature
 * and chain-hash exchange, CreateSession negotiation (altruist policy), and
 * StateUpdate acks for justice blobs built from REAL revoked commitments
 * (sequence advances across multiple updates, backlog drains). Per-blob-type
 * sessions are exercised live: the anchor (v0 kit, blob type 6) and taproot
 * (v1 kit, blob type 10) sessions each negotiate over their own session-keyed
 * connection and get backups acked — LND v0.20's tower accepts all three
 * altruist blob types (blob.IsSupportedType). The justice blob byte formats
 * are verified against LND source semantics and chain-monitor derivations in
 * tests/lightning/watchtower.test.ts and watchtower-taproot.test.ts.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import { execSync } from 'child_process';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';

import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../../src/lightning/channel/types';
import { Channel } from '../../../src/lightning/channel/channel';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { MessageType } from '../../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../../src/lightning/message/channel-funding';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../../src/lightning/message/channel-commitment';
import { buildRemoteCommitment } from '../../../src/lightning/channel/commitment-builder';
import { perCommitmentPointFromSecret } from '../../../src/lightning/keys/derivation';
import { MAX_INDEX } from '../../../src/lightning/keys/shachain';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { FeatureFlags, Feature } from '../../../src/lightning/features/flags';
import { IJusticeContext } from '../../../src/lightning/watchtower/justice';
import { WatchtowerClient } from '../../../src/lightning/watchtower/watchtower-client';
import { chainHashForNetwork } from '../../../src/lightning/watchtower';
import { BlobType } from '../../../src/lightning/watchtower/blob';

bitcoin.initEccLib(ecc);

const network = bitcoin.networks.regtest;
const TOWER_HOST = '127.0.0.1';
const TOWER_PORT = 9911;
const testTimeout = 120000;

interface ITowerLogEvent {
	subsystem: string;
	event: string;
	[key: string]: unknown;
}

function lndTowerPubkey(): string {
	const out = execSync('docker exec lnd lncli --network=regtest tower info', {
		encoding: 'utf8'
	});
	const info = JSON.parse(out);
	return info.pubkey as string;
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

/** One commitment round; the acceptor reveals a revocation secret. */
function exchangeOnce(opener: Channel, acceptor: Channel): void {
	const csActions = opener.signCommitment(crypto.randomBytes(64), []);
	const csMsg = findSendAction(csActions, MessageType.COMMITMENT_SIGNED);
	const raaActions = acceptor.handleCommitmentSigned(
		decodeCommitmentSignedMessage(csMsg.payload)
	);
	const raaMsg = findSendAction(raaActions, MessageType.REVOKE_AND_ACK);
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(raaMsg.payload));
}

type ChannelKind = 'legacy' | 'anchor' | 'taproot';

function channelTypeFor(kind: ChannelKind): Buffer | null {
	if (kind === 'legacy') return null;
	const flags = FeatureFlags.empty();
	if (kind === 'anchor') {
		flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
		flags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
	} else {
		flags.setCompulsory(Feature.OPTION_TAPROOT);
	}
	return flags.toBuffer();
}

/**
 * Drive a real channel to NORMAL with random funding (unique breach txids per
 * run), advance `rounds` commitments, and return one justice context per
 * revoked state (opener's view of the acceptor's revoked commitments). For
 * anchor/taproot kinds the negotiated channel_type is flipped before the
 * revoked commitments are rebuilt, so the contexts carry real anchor/taproot
 * format commitments (the chain-monitor fixture pattern).
 */
function buildRevokedContexts(
	rounds: number,
	kind: ChannelKind = 'legacy'
): IJusticeContext[] {
	const { basepoints: openerBp, privkeys: openerPrivkeys } = makeBasepoints(
		crypto.randomBytes(32)
	);
	const { basepoints: acceptorBp } = makeBasepoints(crypto.randomBytes(32));
	const temporaryChannelId = crypto.randomBytes(32);
	const opener = new Channel(
		createOpenerState({
			temporaryChannelId,
			fundingSatoshis: 1_000_000n,
			pushMsat: 200_000_000n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBp,
			localPerCommitmentSeed: crypto.randomBytes(32)
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId,
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptorBp,
			localPerCommitmentSeed: crypto.randomBytes(32),
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

	for (let i = 0; i < rounds; i++) {
		exchangeOnce(opener, acceptor);
	}

	const state = opener.getFullState();
	state.channelType = channelTypeFor(kind);
	const sweepScript = bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(crypto.randomBytes(32)),
		network
	}).output!;
	const contexts: IJusticeContext[] = [];
	for (let i = 0; i < rounds; i++) {
		const secret = state.shaChainStore.getSecret(MAX_INDEX - BigInt(i));
		expect(secret, `revoked secret ${i} present`).to.not.be.null;
		const revokedPoint = perCommitmentPointFromSecret(secret!);
		const built = buildRemoteCommitment(state, revokedPoint, BigInt(i));
		contexts.push({
			channelId: `wt-lnd-interop-${kind}-${i}`,
			revokedTx: built.result.tx,
			perCommitmentSecret: secret!,
			revocationBasepoint: state.localBasepoints.revocationBasepoint,
			revocationBasepointSecret: openerPrivkeys[1],
			remoteDelayedBasepoint: state.remoteBasepoints!.delayedPaymentBasepoint,
			toSelfDelay: state.localConfig.toSelfDelay,
			isAnchor: kind !== 'legacy',
			isTaproot: kind === 'taproot',
			localPaymentPubkey: state.localBasepoints.paymentBasepoint,
			paymentBasepointSecret: openerPrivkeys[2],
			sweepScript,
			network
		});
	}
	return contexts;
}

/** Wait for a specific watchtower log event, failing fast on tower errors. */
function waitForEvent(
	events: ITowerLogEvent[],
	client: WatchtowerClient,
	event: string,
	timeoutMs: number
): Promise<ITowerLogEvent> {
	return new Promise((resolve, reject) => {
		const existing = events.find((e) => e.event === event);
		if (existing) {
			resolve(existing);
			return;
		}
		const timer = setTimeout(() => {
			client.removeListener('log', onLog);
			reject(
				new Error(
					`Timed out waiting for "${event}"; saw: ${events
						.map((e) => e.event)
						.join(', ')}`
				)
			);
		}, timeoutMs);
		const failEvents = new Set([
			'tower_error',
			'tower_wt_error',
			'connect_failed',
			'session_error',
			'update_rejected',
			'backup_failed'
		]);
		function onLog(e: ITowerLogEvent): void {
			if (e.event === event) {
				clearTimeout(timer);
				client.removeListener('log', onLog);
				resolve(e);
			} else if (failEvents.has(e.event)) {
				clearTimeout(timer);
				client.removeListener('log', onLog);
				reject(
					new Error(`Tower failure event "${e.event}": ${JSON.stringify(e)}`)
				);
			}
		}
		client.on('log', onLog);
	});
}

/** Wait for a watchtower log event matching a predicate, failing on errors. */
function waitForMatch(
	events: ITowerLogEvent[],
	client: WatchtowerClient,
	desc: string,
	match: (e: ITowerLogEvent) => boolean,
	timeoutMs: number
): Promise<ITowerLogEvent> {
	return new Promise((resolve, reject) => {
		const existing = events.find(match);
		if (existing) {
			resolve(existing);
			return;
		}
		const timer = setTimeout(() => {
			client.removeListener('log', onLog);
			reject(
				new Error(
					`Timed out waiting for ${desc}; saw: ${events
						.map((e) => e.event)
						.join(', ')}`
				)
			);
		}, timeoutMs);
		const failEvents = new Set([
			'tower_error',
			'tower_wt_error',
			'connect_failed',
			'session_error',
			'session_rejected',
			'update_rejected',
			'backup_failed'
		]);
		function onLog(e: ITowerLogEvent): void {
			if (match(e)) {
				clearTimeout(timer);
				client.removeListener('log', onLog);
				resolve(e);
			} else if (failEvents.has(e.event)) {
				clearTimeout(timer);
				client.removeListener('log', onLog);
				reject(
					new Error(`Tower failure event "${e.event}": ${JSON.stringify(e)}`)
				);
			}
		}
		client.on('log', onLog);
	});
}

describe('watchtower client vs live LND tower', function () {
	this.timeout(testTimeout);

	let towerUri: string;
	let client: WatchtowerClient;
	const events: ITowerLogEvent[] = [];

	before(function () {
		const pubkey = lndTowerPubkey();
		towerUri = `${pubkey}@${TOWER_HOST}:${TOWER_PORT}`;
	});

	after(function () {
		client?.stop();
	});

	it('negotiates a session with the real LND tower', async function () {
		client = new WatchtowerClient({
			localPrivateKey: crypto.randomBytes(32),
			chainHash: chainHashForNetwork(network),
			network,
			towers: [towerUri]
		});
		client.on('log', (e: ITowerLogEvent) => events.push(e));
		const sessionCreated = waitForEvent(
			events,
			client,
			'session_created',
			30000
		);
		await client.start();
		const created = await sessionCreated;
		expect(created.tower).to.equal(towerUri);
	});

	it('gets a real revoked-commitment backup acked (seq 1)', async function () {
		const [ctx] = buildRevokedContexts(1);
		const acked = waitForEvent(events, client, 'update_acked', 30000);
		client.backupRevokedState(ctx);
		const ack = await acked;
		expect(ack.seqNum).to.equal(1);
	});

	it('advances the sequence across further revoked states', async function () {
		const contexts = buildRevokedContexts(2);
		for (let i = 0; i < contexts.length; i++) {
			const before = events.filter((e) => e.event === 'update_acked').length;
			const acked = new Promise<ITowerLogEvent>((resolve, reject) => {
				const timer = setTimeout(
					() => reject(new Error(`ack ${i + 2} timed out`)),
					30000
				);
				function onLog(e: ITowerLogEvent): void {
					if (
						e.event === 'update_acked' &&
						events.filter((x) => x.event === 'update_acked').length > before
					) {
						clearTimeout(timer);
						client.removeListener('log', onLog);
						resolve(e);
					}
				}
				client.on('log', onLog);
			});
			client.backupRevokedState(contexts[i]);
			const ack = await acked;
			expect(ack.seqNum).to.equal(i + 2);
		}
	});

	it('negotiates an anchor session and gets an anchor v0 backup acked', async function () {
		// Anchor channels use blob type 6 (FlagCommitOutputs|FlagAnchorChannel):
		// a separate session over its own session-keyed connection, since LND
		// towers accept one blob type per session (keyed to the connection pub).
		const [ctx] = buildRevokedContexts(1, 'anchor');
		const sessionCreated = waitForMatch(
			events,
			client,
			'anchor session_created',
			(e) =>
				e.event === 'session_created' &&
				e.blobType === BlobType.ALTRUIST_ANCHOR_COMMIT,
			30000
		);
		const acked = waitForMatch(
			events,
			client,
			'anchor update_acked',
			(e) =>
				e.event === 'update_acked' &&
				e.blobType === BlobType.ALTRUIST_ANCHOR_COMMIT,
			30000
		);
		client.backupRevokedState(ctx);
		await sessionCreated;
		const ack = await acked;
		// Fresh session for this blob type: its sequence starts at 1 even though
		// the legacy session has already shipped several updates.
		expect(ack.seqNum).to.equal(1);
	});

	it('negotiates a taproot session (LND v0.20 accepts blob type 10) and gets a v1 backup acked', async function () {
		// LND v0.20's tower supports TypeAltruistTaprootCommit
		// (watchtower/blob/type.go supportedTypes), even though its Init only
		// advertises anchor-optional; CreateSession succeeds. If a tower ever
		// rejects (CreateSessionCodeRejectBlobType 64), the client queues taproot
		// backups instead of crashing (covered offline in watchtower-taproot).
		const [ctx] = buildRevokedContexts(1, 'taproot');
		const sessionCreated = waitForMatch(
			events,
			client,
			'taproot session_created',
			(e) =>
				e.event === 'session_created' &&
				e.blobType === BlobType.ALTRUIST_TAPROOT_COMMIT,
			30000
		);
		const acked = waitForMatch(
			events,
			client,
			'taproot update_acked',
			(e) =>
				e.event === 'update_acked' &&
				e.blobType === BlobType.ALTRUIST_TAPROOT_COMMIT,
			30000
		);
		client.backupRevokedState(ctx);
		await sessionCreated;
		const ack = await acked;
		expect(ack.seqNum).to.equal(1);
		// All three blob-type sessions now live against the same tower.
		const health = client.getHealth();
		expect(health[0].sessions).to.equal(3);
		expect(health[0].pendingBacklog).to.equal(0);
	});

	it('a fresh client with a new identity negotiates its own session', async function () {
		const other = new WatchtowerClient({
			localPrivateKey: crypto.randomBytes(32),
			chainHash: chainHashForNetwork(network),
			network,
			towers: [towerUri]
		});
		const otherEvents: ITowerLogEvent[] = [];
		other.on('log', (e: ITowerLogEvent) => otherEvents.push(e));
		try {
			const sessionCreated = waitForEvent(
				otherEvents,
				other,
				'session_created',
				30000
			);
			await other.start();
			const created = await sessionCreated;
			expect(created.tower).to.equal(towerUri);
			const [ctx] = buildRevokedContexts(1);
			const acked = waitForEvent(otherEvents, other, 'update_acked', 30000);
			other.backupRevokedState(ctx);
			const ack = await acked;
			expect(ack.seqNum).to.equal(1);
		} finally {
			other.stop();
		}
	});
});
