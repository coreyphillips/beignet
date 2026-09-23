/**
 * Issue #989: a failed HTLC is retried, and counts as no longer in flight,
 * only once its removal is irrevocable.
 *
 * The peer's update_fail_htlc marks the offered HTLC FAILED with both
 * removal phase flags still false, and the node's fail handler re-entered
 * the senders from that very action, before the peer's revoke_and_ack for
 * the removal. Until that revocation the peer's last signed commitment
 * still carries the HTLC: a hop that failed it early and later obtains the
 * preimage (from the retry's route) can go to chain with that commitment
 * and claim it while the retry also settles. And #975's dedup deliberately
 * did not count a 'failed' view as in flight, because the immediate retry
 * depended on it, so a manual re-send was admitted in the same window.
 *
 * The fail handler now parks its own payment's failure while the channel
 * still holds the entry as a provisional FAILED, exactly as it already held
 * a forward's fail back (issue #623), and the revoke_and_ack that completes
 * the removal drains it: the retry goes out one round later, or the record
 * is given up. A 'failed' HTLC counts as in flight until it is terminal, so
 * a re-send in the window is refused and a timeout in the window keeps the
 * record PENDING with the retry budget frozen.
 *
 * The pair here relays messages synchronously and can hold bob's
 * revoke_and_ack, so the window can be held open and inspected, then
 * released.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	IPaymentRetryContext,
	LightningErrorCode,
	LightningPaymentError,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { createFailureMessage } from '../../src/lightning/onion/failures';
import { TEMPORARY_NODE_FAILURE } from '../../src/lightning/onion/types';
import { MessageType } from '../../src/lightning/message/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`irrevocable-seed-${id}`))
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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
}

function createNode(seedId: number, storage?: SqliteStorage): LightningNode {
	const node = new LightningNode({
		...makeNodeConfig(seedId),
		...(storage ? { storage } : {})
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

const CHANNEL_SCID = encodeShortChannelId({
	block: 500,
	txIndex: 1,
	outputIndex: 0
});

/** Bob's revoke_and_ack messages to alice are held while `hold` is set. */
interface IRevokeGate {
	hold: boolean;
	held: Array<{ type: number; payload: Buffer }>;
}

/**
 * Two nodes wired back to back with one ready channel from alice to bob.
 * `release` delivers every held revoke_and_ack, in order, and lets the
 * next ones through.
 */
function setupPair(
	aliceSeed: number,
	bobSeed: number,
	aliceStorage?: SqliteStorage
): {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	gate: IRevokeGate;
	release: () => void;
} {
	const alice = createNode(aliceSeed, aliceStorage);
	const bob = createNode(bobSeed);
	const gate: IRevokeGate = { hold: false, held: [] };

	alice.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === bob.getNodeId()) {
			bob.handlePeerMessage(alice.getNodeId(), type, payload);
		}
	});
	bob.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey !== alice.getNodeId()) return;
		if (gate.hold && type === MessageType.REVOKE_AND_ACK) {
			gate.held.push({ type, payload: Buffer.from(payload) });
			return;
		}
		alice.handlePeerMessage(bob.getNodeId(), type, payload);
	});
	const release = (): void => {
		gate.hold = false;
		for (const m of gate.held.splice(0)) {
			alice.handlePeerMessage(bob.getNodeId(), m.type, m.payload);
		}
	};

	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	alice.registerChannelScid(channelId, CHANNEL_SCID);
	return { alice, bob, channelId, gate, release };
}

/** The hashes of the payment:sent and payment:failed events a node emits from now on. */
function recordEvents(node: LightningNode): {
	sent: string[];
	failed: string[];
} {
	const sent: string[] = [];
	const failed: string[] = [];
	node.on('payment:sent', (info: IPaymentInfo) =>
		sent.push(info.paymentHash.toString('hex'))
	);
	node.on('payment:failed', (info: IPaymentInfo) =>
		failed.push(info.paymentHash.toString('hex'))
	);
	return { sent, failed };
}

/** The message a wait rejected with, or '' if it resolved. */
async function rejectionOf(wait: Promise<unknown>): Promise<string> {
	try {
		await wait;
		return '';
	} catch (err: unknown) {
		return err instanceof Error ? err.message : String(err);
	}
}

/** Counts the update_add_htlc messages a node sends from now on. */
function countAdds(node: LightningNode): () => number {
	let adds = 0;
	node.on('message:outbound', (_pubkey: string, type: number) => {
		if (type === MessageType.UPDATE_ADD_HTLC) adds++;
	});
	return () => adds;
}

/** Bob's insides: the final-hop handler a test replaces, and what fails an HTLC back. */
type Payee = {
	handleFinalHopHtlc: (...args: unknown[]) => unknown;
	receivedHtlcSharedSecrets: Map<string, Buffer>;
	preimages: Map<string, Buffer>;
	channelManager: {
		failHtlc: (channelId: Buffer, htlcId: bigint, reason: Buffer) => unknown;
	};
};
const payee = (bob: LightningNode): Payee => bob as unknown as Payee;

/**
 * Bob fails the first HTLC he receives back with a temporary failure (the
 * answer the retry path meets by dispatching again) and accepts every later
 * one. With a gate, bob's revoke_and_ack messages are held from the moment
 * he fails, so the round that would make the removal irrevocable stops one
 * message short until the test releases it.
 */
function failFirstAttempt(
	bob: LightningNode,
	gate?: IRevokeGate
): { attempts: () => number; first: () => [Buffer, bigint] | undefined } {
	const b = payee(bob);
	const accept = b.handleFinalHopHtlc;
	let attempts = 0;
	let first: [Buffer, bigint] | undefined;
	b.handleFinalHopHtlc = (...args: unknown[]): unknown => {
		attempts++;
		if (attempts > 1) return accept.apply(bob, args);
		const [channelId, htlcId] = args as [Buffer, bigint];
		first = [channelId, htlcId];
		const sharedSecret = b.receivedHtlcSharedSecrets.get(
			`${channelId.toString('hex')}:${htlcId}`
		);
		expect(sharedSecret, 'bob kept the shared secret').to.not.equal(undefined);
		if (gate) gate.hold = true;
		b.channelManager.failHtlc(
			channelId,
			htlcId,
			createFailureMessage(sharedSecret!, TEMPORARY_NODE_FAILURE)
		);
		return undefined;
	};
	return { attempts: () => attempts, first: () => first };
}

type Internals = {
	retriesAwaitingRemoval: Map<string, unknown>;
	htlcPaymentMap: Map<string, string>;
	paymentRetryContexts: Map<string, IPaymentRetryContext>;
	payments: Map<string, IPaymentInfo>;
	scanStuckPayments: () => void;
	channelManager: {
		emit: (event: string, ...args: unknown[]) => boolean;
	};
};
const internals = (node: LightningNode): Internals =>
	node as unknown as Internals;

/** The offered entry alice's channel holds for the HTLC, if any. */
function offeredEntry(
	alice: LightningNode,
	channelId: Buffer,
	htlcId: bigint
): { state: HtlcState; removalRemoteCommitted?: boolean } | undefined {
	return alice
		.getChannelManager()
		.getChannel(channelId)
		?.getFullState()
		.htlcs.get(`offered-${htlcId}`);
}

/** What a send threw, or undefined if it went out. */
function refusalOf(send: () => unknown): unknown {
	try {
		send();
		return undefined;
	} catch (err: unknown) {
		return err;
	}
}

function tempDb(prefix: string): string {
	return path.join(
		fs.mkdtempSync(path.join(os.tmpdir(), `beignet-${prefix}-`)),
		'node.db'
	);
}

async function settle(rounds = 4): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

/**
 * Reconnect a restarted node to its live peer the way a real socket pair
 * delivers: both channel_reestablish messages cross before any responses.
 */
async function reconnect(
	restarted: LightningNode,
	peer: LightningNode
): Promise<void> {
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
	rewire(restarted, peer);
	rewire(peer, restarted);
	restarted.getChannelManager().handlePeerReconnected(peer.getNodeId());
	peer.getChannelManager().handlePeerReconnected(restarted.getNodeId());
	while (queue.length > 0) {
		const m = queue.shift()!;
		m.to.handlePeerMessage(m.from, m.type, m.payload);
	}
	hold = false;
	await settle();
}

describe('Issue #989: a failed HTLC is retried only once its removal is irrevocable', () => {
	it('holds the retry and refuses a re-send while the peer has not revoked for the removal, then retries once it has', () => {
		const { alice, bob, channelId, gate, release } = setupPair(980, 981);
		const { attempts, first } = failFirstAttempt(bob, gate);
		const events = recordEvents(alice);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'deferred retry'
		});
		const hash = invoice.paymentHash;
		const hashHex = hash.toString('hex');
		const adds = countAdds(alice);

		alice.sendPayment(invoice.bolt11);

		// Bob failed the HTLC; his revoke_and_ack for the removal round is
		// held, so the removal is one revocation short of irrevocable and
		// his last signed commitment still carries the HTLC.
		expect(attempts()).to.equal(1);
		expect(gate.held.length, "bob's revoke_and_ack is held").to.equal(1);
		const [, htlcId] = first()!;
		const entry = offeredEntry(alice, channelId, htlcId);
		expect(entry?.state, 'the entry is a provisional FAILED').to.equal(
			HtlcState.FAILED
		);
		expect(entry?.removalRemoteCommitted).to.equal(false);

		// Before the fix the retry went out here, from the fail itself.
		expect(adds(), 'no retry before the removal is irrevocable').to.equal(1);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		expect(
			alice.hasHtlcInFlight(hash),
			'the failed HTLC is in flight'
		).to.equal(true);
		expect(internals(alice).retriesAwaitingRemoval.size).to.equal(1);
		expect(
			alice.getOutgoingHtlcs(hash).htlcs.map((h) => [h.state, h.terminal])
		).to.deep.equal([['failed', false]]);

		// A manual re-send in the window is refused as in flight.
		const refusal = refusalOf(() => alice.sendPayment(invoice.bolt11));
		expect(refusal).to.be.instanceOf(LightningPaymentError);
		expect((refusal as LightningPaymentError).code).to.equal(
			LightningErrorCode.DUPLICATE_PAYMENT
		);
		expect((refusal as Error).message).to.equal(
			'Payment already in flight for this invoice'
		);
		expect(adds(), 'the refused re-send offered nothing').to.equal(1);
		expect(events.sent).to.deep.equal([]);
		expect(events.failed).to.deep.equal([]);

		// Bob's revoke_and_ack arrives: the removal is irrevocable, the
		// parked failure is settled, and the retry goes out once.
		release();

		expect(attempts(), 'the retry was dispatched').to.equal(2);
		expect(adds()).to.equal(2);
		const record = alice.getPayment(hash);
		expect(record?.status).to.equal(PaymentStatus.COMPLETED);
		expect(record?.retryCount).to.equal(1);
		expect(events.sent).to.deep.equal([hashHex]);
		expect(events.failed).to.deep.equal([]);
		expect(internals(alice).retriesAwaitingRemoval.size).to.equal(0);
		expect(
			internals(alice).htlcPaymentMap.size,
			'neither attempt is left mapped'
		).to.equal(0);
		expect(offeredEntry(alice, channelId, htlcId)).to.equal(undefined);

		alice.destroy();
		bob.destroy();
	});

	it('still retries and completes when the removal round runs to the end', () => {
		const { alice, bob } = setupPair(982, 983);
		const { attempts } = failFirstAttempt(bob);
		const events = recordEvents(alice);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'plain retry'
		});
		const hash = invoice.paymentHash;
		const adds = countAdds(alice);

		alice.sendPayment(invoice.bolt11);

		// The relay is synchronous: the removal round completed inside the
		// send, and the retry followed it.
		expect(attempts()).to.equal(2);
		expect(adds()).to.equal(2);
		const record = alice.getPayment(hash);
		expect(record?.status).to.equal(PaymentStatus.COMPLETED);
		expect(record?.retryCount).to.equal(1);
		expect(events.sent).to.deep.equal([hash.toString('hex')]);
		expect(events.failed).to.deep.equal([]);
		expect(alice.hasHtlcInFlight(hash)).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it('drops the parked failure when the HTLC is fulfilled after all, and retries nothing', () => {
		// A disconnect before our revocation rolls the fail back to
		// COMMITTED and the peer may retransmit a fulfil instead. Driving
		// bob through a lost fail needs surgery on his state, so the fulfil
		// is injected at alice's channel manager event while the failure
		// is parked: what the node does with it is what is under test.
		const { alice, bob, channelId, gate, release } = setupPair(984, 985);
		const { attempts, first } = failFirstAttempt(bob, gate);
		const events = recordEvents(alice);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'fulfilled after a rollback'
		});
		const hash = invoice.paymentHash;
		const hashHex = hash.toString('hex');
		const preimage = payee(bob).preimages.get(hashHex);
		expect(preimage, 'bob holds the preimage of his invoice').to.not.equal(
			undefined
		);
		const adds = countAdds(alice);

		alice.sendPayment(invoice.bolt11);
		expect(adds()).to.equal(1);
		expect(internals(alice).retriesAwaitingRemoval.size).to.equal(1);
		const [, htlcId] = first()!;

		internals(alice).channelManager.emit(
			'htlc:fulfilled',
			channelId,
			htlcId,
			preimage
		);

		expect(
			internals(alice).retriesAwaitingRemoval.size,
			'the parked failure is void'
		).to.equal(0);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(alice.getPayment(hash)?.preimage?.equals(preimage!)).to.equal(true);
		expect(events.sent).to.deep.equal([hashHex]);

		// The round that would have drained the failure finds nothing.
		release();
		expect(attempts()).to.equal(1);
		expect(adds(), 'no retry').to.equal(1);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(alice.getPayment(hash)?.retryCount ?? 0).to.equal(0);
		expect(events.failed).to.deep.equal([]);
		expect(internals(alice).paymentRetryContexts.has(hashHex)).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it('a timeout inside the window keeps the record PENDING and freezes the budget, so the drained failure gives up', async () => {
		const { alice, bob, gate, release } = setupPair(986, 987);
		const { attempts } = failFirstAttempt(bob, gate);
		const events = recordEvents(alice);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'timed out in the window'
		});
		const hash = invoice.paymentHash;
		const hashHex = hash.toString('hex');
		const adds = countAdds(alice);

		const message = await rejectionOf(
			alice.sendPaymentAsync(invoice.bolt11, 50)
		);

		// The failed HTLC is in flight until its removal is irrevocable, so
		// the wall clock does not fail the record; it freezes the retries.
		expect(message).to.equal(
			'Payment timed out after 50ms; an HTLC is still in flight and the payment stays PENDING until it resolves; no further route is tried after the timeout'
		);
		expect(attempts()).to.equal(1);
		expect(adds()).to.equal(1);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		const context = internals(alice).paymentRetryContexts.get(hashHex);
		expect(context, 'the context stays').to.not.equal(undefined);
		expect(context!.maxRetries, 'the retry budget is frozen').to.equal(
			context!.retryCount
		);
		expect(events.failed).to.deep.equal([]);

		// The removal completes: the parked failure lands on the give-up
		// path, and bob, who would accept a second attempt, never sees one.
		release();

		expect(attempts()).to.equal(1);
		expect(adds(), 'no retry after the timeout').to.equal(1);
		const record = alice.getPayment(hash);
		expect(record?.status).to.equal(PaymentStatus.FAILED);
		expect(record?.retryCount ?? 0).to.equal(0);
		expect(record?.failureCode).to.equal(TEMPORARY_NODE_FAILURE);
		expect(events.failed).to.deep.equal([hashHex]);
		expect(events.sent).to.deep.equal([]);
		expect(internals(alice).paymentRetryContexts.has(hashHex)).to.equal(false);
		expect(internals(alice).retriesAwaitingRemoval.size).to.equal(0);
		expect(alice.hasHtlcInFlight(hash)).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it('a restart inside the window loses the retry, never the payment: the record stays PENDING until the stuck sweep', async function () {
		this.timeout(20_000);
		const dbPath = tempDb('989-restart');
		const storage1 = new SqliteStorage(dbPath);
		storage1.open();
		const { alice, bob, gate } = setupPair(988, 989, storage1);
		// Bob would accept a second attempt; none must come.
		const { attempts } = failFirstAttempt(bob, gate);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'restart in the window'
		});
		const hash = invoice.paymentHash;
		const hashHex = hash.toString('hex');
		const adds = countAdds(alice);

		alice.sendPayment(invoice.bolt11);
		expect(attempts()).to.equal(1);
		expect(adds()).to.equal(1);
		expect(gate.held.length, "bob's revoke_and_ack is held").to.equal(1);
		expect(alice.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);

		// Alice restarts from her database; the parked failure was memory.
		alice.destroy();
		storage1.close();
		bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
		bob.removeAllListeners('message:outbound');
		const storage2 = new SqliteStorage(dbPath);
		storage2.open();
		const restarted = createNode(988, storage2);
		const restartedAdds = countAdds(restarted);
		const events = recordEvents(restarted);
		expect(
			restarted.getPayment(hash)?.status,
			'the record was durable'
		).to.equal(PaymentStatus.PENDING);

		// On reestablish bob retransmits the revoke_and_ack alice never got:
		// the removal completes, and nothing is parked to retry from.
		await reconnect(restarted, bob);
		const channel = restarted.getChannelManager().listChannels()[0];
		expect(channel.getState()).to.equal(ChannelState.NORMAL);
		expect(channel.getFullState().htlcs.size, 'the removal completed').to.equal(
			0
		);
		expect(attempts()).to.equal(1);
		expect(restartedAdds(), 'no retry after the restart').to.equal(0);
		expect(restarted.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		expect(restarted.hasHtlcInFlight(hash)).to.equal(false);
		expect(internals(restarted).retriesAwaitingRemoval.size).to.equal(0);

		// The stuck-payment sweep fails it once it is ten minutes old.
		internals(restarted).scanStuckPayments();
		expect(restarted.getPayment(hash)?.status, 'not before').to.equal(
			PaymentStatus.PENDING
		);
		internals(restarted).payments.get(hashHex)!.createdAt =
			Date.now() - 11 * 60_000;
		internals(restarted).scanStuckPayments();
		expect(restarted.getPayment(hash)?.status).to.equal(PaymentStatus.FAILED);
		expect(events.failed).to.deep.equal([hashHex]);
		expect(events.sent).to.deep.equal([]);

		restarted.destroy();
		bob.destroy();
		storage2.close();
	});
});
