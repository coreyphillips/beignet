/**
 * A retransmitted revoke_and_ack on a taproot channel must carry
 * next_local_nonce, or the peer that asked for it cannot resume the
 * interrupted commitment round (issue 293).
 *
 * The original revoke_and_ack attaches our next-commitment verification
 * nonce, and the taproot revoke_and_ack handler requires it
 * unconditionally. The reestablish retransmission path rebuilt the message
 * from the persisted secret and next point alone, so the replayed revoke
 * arrived nonce-less and was rejected. Everything after that is a knock-on
 * with a misleading face: the peer's replayed commitment_signed then fails
 * verification too, not because any nonce mismatches (verification nonces
 * are deterministic per height and re-derive identically after a restart),
 * but because the rejected revoke never promoted the pending add
 * (addRemoteCommitted stays false), so the local commitment is rebuilt
 * without the HTLC and the sighash cannot match what the peer signed. The
 * round stalls with the HTLC committed on both sides until its CLTV.
 *
 * A plain channel resumes through the identical shape because its rebuilt
 * revoke_and_ack needs no nonce, which is what made the defect look
 * taproot-specific in the chaos matrix.
 *
 * The fix re-attaches the nonce in the rebuild. It is deterministic per
 * commitment height, so the retransmission advertises byte-identically
 * what the original did, which the live regression asserts directly.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	BITCOIN_CHAIN_HASH,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { decodeRevokeAndAckMessage } from '../../src/lightning/message/channel-commitment';
import {
	IRecoveryCommitResult,
	SafetyTransition
} from '../../src/lightning/recovery/types';

const ALICE_SEED = 86;
const BOB_SEED = 87;

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`tr-raa-seed-${id}`).digest();
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

function makeNodeConfig(
	seedId: number,
	storage?: IStorageBackend
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		storage,
		preferTaproot: true
	};
}

function createNode(seedId: number, storage?: IStorageBackend): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/**
 * Storage that stops accepting writes once the process is "dead". Reads
 * pass through; close stays callable so destroy() can release the file.
 */
function sealableStorage(
	inner: IStorageBackend,
	dead: { val: boolean }
): IStorageBackend {
	return new Proxy(inner, {
		get(target, prop, receiver): unknown {
			const value = Reflect.get(target, prop, receiver);
			if (typeof value !== 'function') return value;
			if (dead.val && prop !== 'close') {
				return (): undefined => undefined;
			}
			return value.bind(target);
		}
	}) as IStorageBackend;
}

interface IDeadSwitch {
	val: boolean;
}

/**
 * Wire the pair with a mid-round cut: the moment Alice's commitment_signed
 * crosses, the connection dies BEHIND it. Bob processes the commitment and
 * emits his revoke_and_ack + commitment_signed into the dead wire, which
 * is exactly the shape issue 293 kills at (post-send of the commitment).
 */
function wireWithCutAfterCommitment(
	alice: LightningNode,
	bob: LightningNode,
	dead: IDeadSwitch,
	armed: { val: boolean }
): void {
	alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (pk !== bob.getNodeId()) return;
		if (dead.val) return;
		if (armed.val && t === MessageType.COMMITMENT_SIGNED) {
			// The commitment reaches Bob; everything after it finds the wire
			// gone, including Bob's synchronous responses.
			dead.val = true;
			bob.handlePeerMessage(alice.getNodeId(), t, p);
			return;
		}
		bob.handlePeerMessage(alice.getNodeId(), t, p);
	});
	bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
		if (pk !== alice.getNodeId()) return;
		if (dead.val) return;
		alice.handlePeerMessage(bob.getNodeId(), t, p);
	});
}

async function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode
): Promise<Buffer> {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	await settle();
	return channelId;
}

function buildDirectGraph(payer: LightningNode, payeeSeedId: number): void {
	const payerPubkey = payer.getNodeId();
	const payeePubkey = getPublicKey(makeNodeConfig(payeeSeedId).nodePrivateKey);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });
	const payerBuf = Buffer.from(payerPubkey, 'hex');
	const payerIsNode1 = Buffer.compare(payerBuf, payeePubkey) < 0;
	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: payerIsNode1 ? payerBuf : payeePubkey,
		nodeId2: payerIsNode1 ? payeePubkey : payerBuf,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	payer.getGraph().addChannelAnnouncement(announcement);
	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	payer.getGraph().applyChannelUpdate(update);
	payer.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });
	payer.registerChannelScid(
		payer.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

async function settle(rounds = 6): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

/**
 * Reconnect two nodes the way a real socket pair delivers: both
 * channel_reestablish messages cross before any responses.
 */
async function reconnect(a: LightningNode, b: LightningNode): Promise<void> {
	const queue: Array<{
		to: LightningNode;
		from: string;
		type: number;
		payload: Buffer;
	}> = [];
	let hold = true;
	const rewire = (from: LightningNode, to: LightningNode): void => {
		from.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== to.getNodeId()) return;
			if (hold) {
				queue.push({ to, from: from.getNodeId(), type: t, payload: p });
			} else {
				to.handlePeerMessage(from.getNodeId(), t, p);
			}
		});
	};
	rewire(a, b);
	rewire(b, a);
	a.getChannelManager().handlePeerReconnected(b.getNodeId());
	b.getChannelManager().handlePeerReconnected(a.getNodeId());
	while (queue.length > 0) {
		const m = queue.shift()!;
		m.to.handlePeerMessage(m.from, m.type, m.payload);
	}
	hold = false;
	await settle();
}

function assertRoundComplete(
	alice: LightningNode,
	bob: LightningNode,
	payment: { status: PaymentStatus }
): void {
	expect(payment.status, 'payment settled after resume').to.equal(
		PaymentStatus.COMPLETED
	);
	for (const [who, node] of [
		['payer', alice],
		['payee', bob]
	] as const) {
		const state = node.getChannelManager().listChannels()[0].getFullState();
		expect(
			state.localCommitmentNumber,
			`${who} local commitment advanced`
		).to.equal(2n);
		expect(
			state.remoteCommitmentNumber,
			`${who} remote commitment advanced`
		).to.equal(2n);
		expect(state.htlcs.size, `${who} carries no stuck HTLC`).to.equal(0);
	}
}

describe('Taproot reestablish retransmits a usable revoke_and_ack (issue 293)', () => {
	it('a reconnect mid-round resumes: the rebuilt revoke carries the same nonce the original did', async function () {
		this.timeout(20_000);
		const alice = createNode(ALICE_SEED);
		const bob = createNode(BOB_SEED);
		const dead: IDeadSwitch = { val: false };
		const armed = { val: false };
		wireWithCutAfterCommitment(alice, bob, dead, armed);

		// Capture every revoke_and_ack Bob emits, delivered or not, so the
		// original (lost) advertisement can be compared with the rebuilt one.
		const bobRevokes: Buffer[] = [];
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (t === MessageType.REVOKE_AND_ACK) bobRevokes.push(Buffer.from(p));
		});

		await openReadyChannel(alice, bob);
		buildDirectGraph(alice, BOB_SEED);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'taproot resume live'
		});
		armed.val = true;
		const payment = alice.sendPayment(invoice.bolt11);
		await settle();
		expect(payment.status, 'round interrupted by the cut').to.equal(
			PaymentStatus.PENDING
		);
		expect(bobRevokes.length, 'the original revoke died on the wire').to.equal(
			1
		);

		alice.getChannelManager().handlePeerDisconnected(bob.getNodeId());
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
		alice.removeAllListeners('message:outbound');
		bob.removeAllListeners('message:outbound');
		bob.on('message:outbound', (_pk: string, t: number, p: Buffer) => {
			if (t === MessageType.REVOKE_AND_ACK) bobRevokes.push(Buffer.from(p));
		});
		await reconnect(alice, bob);
		await settle(10);

		assertRoundComplete(alice, bob, payment);
		expect(
			bobRevokes.length,
			'exactly one retransmitted revoke'
		).to.be.at.least(2);
		const original = decodeRevokeAndAckMessage(bobRevokes[0]);
		const rebuilt = decodeRevokeAndAckMessage(bobRevokes[1]);
		expect(
			rebuilt.nextLocalNonce,
			'rebuilt revoke advertises a verification nonce'
		).to.not.equal(undefined);
		expect(
			Buffer.from(rebuilt.nextLocalNonce!).equals(
				Buffer.from(original.nextLocalNonce!)
			),
			'the rebuilt revoke advertises byte-identically what the original did'
		).to.equal(true);

		alice.destroy();
		bob.destroy();
	});

	it('a payer restart mid-round resumes through the retransmitted revoke and replayed commitment', async function () {
		this.timeout(20_000);
		const dbPath = tempDb('tr-raa');
		const raw = new SqliteStorage(dbPath);
		raw.open();
		const dead: IDeadSwitch = { val: false };
		const armed = { val: false };
		const alice = createNode(ALICE_SEED, sealableStorage(raw, dead));
		const bob = createNode(BOB_SEED);
		wireWithCutAfterCommitment(alice, bob, dead, armed);

		// The wire cut plays the kill's send half; this plays its storage
		// half: nothing commits after the wire died.
		const holder = alice as unknown as {
			recovery: {
				commit: (transition: SafetyTransition) => IRecoveryCommitResult;
			};
		};
		const realCommit = holder.recovery.commit.bind(holder.recovery);
		holder.recovery.commit = (
			transition: SafetyTransition
		): IRecoveryCommitResult => {
			if (dead.val) {
				return {
					committed: false,
					released: [],
					frameSequence: null,
					error: new Error('crashed')
				} as unknown as IRecoveryCommitResult;
			}
			return realCommit(transition);
		};

		await openReadyChannel(alice, bob);
		buildDirectGraph(alice, BOB_SEED);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'taproot resume restart'
		});
		armed.val = true;
		const payment = alice.sendPayment(invoice.bolt11);
		await settle();
		expect(payment.status, 'round interrupted by the kill').to.equal(
			PaymentStatus.PENDING
		);
		alice.destroy();
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
		bob.removeAllListeners('message:outbound');

		// The disk holds exactly the issue 293 shape: our commitment sent
		// (remote number advanced), nothing of the peer's response durable.
		const inspect = new SqliteStorage(dbPath);
		inspect.open();
		const row = inspect.loadAllChannels()[0];
		expect(
			row.state.remoteCommitmentNumber,
			'commitment send durable'
		).to.equal(1n);
		expect(row.state.localCommitmentNumber, 'no response processed').to.equal(
			0n
		);
		expect(row.state.htlcs.size, 'the offered HTLC on disk').to.equal(1);

		const restarted = createNode(ALICE_SEED, inspect);
		await reconnect(restarted, bob);
		await settle(10);

		// The payer node restarted, so its payment record is judged from
		// disk: the settled preimage proves completion.
		expect(
			inspect
				.loadAllPreimages()
				.some((p) => p.paymentHash === invoice.paymentHash.toString('hex')),
			'preimage durable after the resumed round settled'
		).to.equal(true);
		for (const [who, node] of [
			['restarted payer', restarted],
			['payee', bob]
		] as const) {
			const state = node.getChannelManager().listChannels()[0].getFullState();
			expect(
				state.localCommitmentNumber,
				`${who} local commitment advanced`
			).to.equal(2n);
			expect(
				state.remoteCommitmentNumber,
				`${who} remote commitment advanced`
			).to.equal(2n);
			expect(state.htlcs.size, `${who} carries no stuck HTLC`).to.equal(0);
		}

		restarted.destroy();
		bob.destroy();
	});
});
