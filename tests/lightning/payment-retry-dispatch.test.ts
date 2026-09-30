/**
 * Regression: payment retry never dispatched.
 *
 * The retry marked the existing payment PENDING and then re-entered
 * sendPayment(), whose deduplication rejects a hash that is already in flight.
 * Every retry therefore threw DUPLICATE_PAYMENT into an empty catch and fell
 * through to marking the payment failed, so a payment that failed for a purely
 * temporary reason was abandoned on the first attempt even though
 * maxPaymentRetries defaults to 3.
 *
 * Nothing covered this, because the catch swallowed the error and blamed it on
 * "no alternative route".
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelResult,
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';
import {
	createFailureMessage,
	wrapFailureMessage
} from '../../src/lightning/onion/failures';
import {
	TEMPORARY_NODE_FAILURE,
	FEE_INSUFFICIENT,
	INCORRECT_CLTV_EXPIRY,
	AMOUNT_BELOW_MINIMUM
} from '../../src/lightning/onion/types';
import { encodeChannelUpdateMessage } from '../../src/lightning/gossip/messages';
import { MessageType } from '../../src/lightning/message/types';
import { signChannelUpdate } from '../../src/lightning/gossip/validation';
import { calculateFee } from '../../src/lightning/gossip/pathfinding';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`retry-seed-${id}`))
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

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function setupPair(
	aliceSeed: number,
	bobSeed: number
): {
	alice: LightningNode;
	bob: LightningNode;
} {
	const alice = createNode(aliceSeed);
	const bob = createNode(bobSeed);

	alice.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === bob.getNodeId()) {
			bob.handlePeerMessage(alice.getNodeId(), type, payload);
		}
	});
	bob.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === alice.getNodeId()) {
			alice.handlePeerMessage(bob.getNodeId(), type, payload);
		}
	});

	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);

	const apk = Buffer.from(alice.getNodeId(), 'hex');
	const bpk = Buffer.from(bob.getNodeId(), 'hex');
	const aliceIsNode1 = Buffer.compare(apk, bpk) < 0;
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });

	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aliceIsNode1 ? apk : bpk,
		nodeId2: aliceIsNode1 ? bpk : apk,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	const update1: IChannelUpdateMessage = {
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

	alice.getGraph().addChannelAnnouncement(announcement);
	alice.getGraph().applyChannelUpdate(update1);
	alice.getGraph().applyChannelUpdate({ ...update1, channelFlags: 1 });
	alice.registerChannelScid(channelId, scid);

	return { alice, bob };
}

/**
 * Make bob reject every incoming HTLC with a TEMPORARY failure, which is
 * explicitly retryable (no PERM bit), and count how many arrive.
 */
function failEveryHtlcTemporarily(
	bob: LightningNode,
	onAttempt?: (attempt: number) => void
): () => number {
	let attempts = 0;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const node = bob as any;
	node.handleFinalHopHtlc = (channelId: Buffer, htlcId: bigint): void => {
		attempts++;
		onAttempt?.(attempts);
		const key = `${channelId.toString('hex')}:${htlcId}`;
		const sharedSecret = node.receivedHtlcSharedSecrets.get(key);
		node.channelManager.failHtlc(
			channelId,
			htlcId,
			createFailureMessage(sharedSecret, TEMPORARY_NODE_FAILURE)
		);
	};
	return () => attempts;
}

describe('Payment retry actually dispatches', () => {
	it('redispatches after a temporary failure', () => {
		const { alice, bob } = setupPair(900, 901);
		const attempts = failEveryHtlcTemporarily(bob);

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'retry'
		});
		alice.sendPayment(invoice.bolt11);

		// Before the fix this was exactly 1: the retry threw DUPLICATE_PAYMENT
		// into an empty catch and the payment was abandoned on first failure.
		expect(
			attempts(),
			'the payment was redispatched at least once'
		).to.be.greaterThan(1);

		alice.destroy();
		bob.destroy();
	});

	it('reports a retry count matching the attempts actually made', () => {
		const { alice, bob } = setupPair(902, 903);
		const attempts = failEveryHtlcTemporarily(bob);

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'retry-count'
		});
		const sent = alice.sendPayment(invoice.bolt11);

		const settled = alice
			.listPayments()
			.find((p) => p.paymentHash.equals(sent.paymentHash));
		expect(settled, 'payment record exists').to.not.be.undefined;
		// retryCount incremented even when nothing was redispatched, so it used to
		// claim a retry that never happened.
		expect(settled!.retryCount ?? 0).to.equal(attempts() - 1);

		alice.destroy();
		bob.destroy();
	});

	// Each attempt gets its own channel/htlc id and its own htlcPaymentMap entry.
	// The cleanup used to live only on the give-up path, so a retry that
	// dispatched returned early and left the failed attempt mapped forever.
	it('releases the failed attempt htlcPaymentMap entry when a retry dispatches', () => {
		const { alice, bob } = setupPair(904, 905);
		failEveryHtlcTemporarily(bob);

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'mapping'
		});
		alice.sendPayment(invoice.bolt11);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const map = (alice as any).htlcPaymentMap as Map<string, string>;
		expect(
			map.size,
			'no failed attempt is left mapped to the payment hash'
		).to.equal(0);

		alice.destroy();
		bob.destroy();
	});

	// The retry used to clear failureCode/failureSourceIndex/failureReason before
	// dispatching, then "restore" that same wiped object when dispatch threw, so a
	// payment could end FAILED explaining nothing at all.
	it('keeps the original failure when the retry cannot be dispatched', () => {
		const { alice, bob } = setupPair(906, 907);
		failEveryHtlcTemporarily(bob, (attempt) => {
			if (attempt === 1) {
				// Make the retry fail to leave the node: no outgoing channel.
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const a = alice as any;
				a.findChannelForPeer = (): null => null;
				a.findLocalChannelByScid = (): null => null;
			}
		});

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'diagnostics'
		});
		const sent = alice.sendPayment(invoice.bolt11);

		const failed = alice
			.listPayments()
			.find((p) => p.paymentHash.equals(sent.paymentHash));
		expect(failed, 'payment record exists').to.not.be.undefined;
		expect(failed!.status).to.equal(PaymentStatus.FAILED);
		expect(
			failed!.failureCode,
			'the onion failure that actually happened survives'
		).to.equal(TEMPORARY_NODE_FAILURE);
		expect(
			(failed!.failureReason ?? '').toLowerCase(),
			'and the retry error is reported, not swallowed'
		).to.contain('retry not dispatched');
		expect(
			failed!.failureReason ?? '',
			'naming the actual dispatch error'
		).to.contain('No channel to first hop');

		alice.destroy();
		bob.destroy();
	});

	// Each attempt replaces the record, so the caller's metadata has to ride
	// the retry context onto every one of them (issue #1152).
	it('carries the caller metadata onto every attempt', () => {
		const { alice, bob } = setupPair(908, 909);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'labelled'
		});
		const seen: Array<Record<string, string> | undefined> = [];
		const labels = { requestId: 'req-1' };
		const attempts = failEveryHtlcTemporarily(bob, () => {
			seen.push(alice.getPayment(invoice.paymentHash)?.metadata);
			// The caller changing its own object must not relabel a retry.
			labels.requestId = 'changed';
		});

		alice.sendPaymentWithOptions(invoice.bolt11, { metadata: labels });

		expect(attempts()).to.be.greaterThan(1);
		expect(seen).to.have.length(attempts());
		for (const metadata of seen) {
			expect(metadata).to.deep.equal({ requestId: 'req-1' });
		}
		const failed = alice.getPayment(invoice.paymentHash)!;
		expect(failed.status).to.equal(PaymentStatus.FAILED);
		expect(failed.metadata).to.deep.equal({ requestId: 'req-1' });

		alice.destroy();
		bob.destroy();
	});

	it("does not relabel a later send's retries with a failed send's metadata", () => {
		const { alice, bob } = setupPair(914, 915);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'relabelled'
		});
		// The first send throws after seeding its retry context.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = alice as any;
		a.findChannelForPeer = (): null => null;
		a.findLocalChannelByScid = (): null => null;
		expect(() =>
			alice.sendPaymentWithOptions(invoice.bolt11, {
				metadata: { requestId: 'first' }
			})
		).to.throw(/No channel to first hop/);
		delete a.findChannelForPeer;
		delete a.findLocalChannelByScid;

		const seen: Array<Record<string, string> | undefined> = [];
		const attempts = failEveryHtlcTemporarily(bob, () => {
			seen.push(alice.getPayment(invoice.paymentHash)?.metadata);
		});
		alice.sendPaymentWithOptions(invoice.bolt11, {
			metadata: { requestId: 'second' }
		});

		expect(attempts()).to.be.greaterThan(1);
		for (const metadata of seen) {
			expect(metadata).to.deep.equal({ requestId: 'second' });
		}
		expect(alice.getPayment(invoice.paymentHash)!.metadata).to.deep.equal({
			requestId: 'second'
		});

		alice.destroy();
		bob.destroy();
	});
});

describe('Retry context lifecycle', () => {
	it('a keysend dispatch that finds no route leaves no retry context', () => {
		const alice = createNode(910);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = alice as any;

		expect(() =>
			alice.sendKeysend({
				destination: Buffer.concat([
					Buffer.from([0x02]),
					crypto.randomBytes(32)
				]),
				amountMsat: 50_000n
			})
		).to.throw(/route/i);
		expect(
			a.paymentRetryContexts.size,
			'no context for a payment that never existed'
		).to.equal(0);

		alice.destroy();
	});

	it('pruneCompletedPayments drops a retry context whose payment is gone', () => {
		const { alice, bob } = setupPair(912, 913);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = alice as any;

		// A live payment's context must survive the prune. Hold the HTLC on
		// bob's side so the payment stays PENDING and its context registered.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(bob as any).handleFinalHopHtlc = (): void => {};
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'live'
		});
		alice.sendPayment(invoice.bolt11);
		const liveContexts = a.paymentRetryContexts.size;
		expect(liveContexts, 'the live payment registered a context').to.be.above(
			0
		);

		// An orphaned one (its dispatch threw after registration) must not.
		a.paymentRetryContexts.set('00'.repeat(32), {
			invoiceStr: 'lnbcrt1invalid',
			excludedChannels: new Set(),
			retryCount: 0,
			maxRetries: 3
		});

		alice.pruneCompletedPayments();
		expect(a.paymentRetryContexts.has('00'.repeat(32))).to.be.false;
		expect(
			a.paymentRetryContexts.size,
			'contexts with a payment record survive'
		).to.equal(liveContexts);

		alice.destroy();
		bob.destroy();
	});
});

describe('Issue #1041: a BOLT 11 send that ended leaves no context for the next', () => {
	// The earlier send asks for ten times the later one's amount under a
	// hundred times its fee cap. This pair carries dust HTLCs only, hence
	// the small sizes.
	const EARLIER = { amountMsat: 200_000n, maxFeeMsat: 10_000n };
	const LATER = { amountMsat: 20_000n, maxFeeMsat: 100n };

	/** Zero-amount invoice from bob, and alice's view of its retry context. */
	function zeroAmountInvoice(
		alice: LightningNode,
		bob: LightningNode
	): { bolt11: string; paymentHash: Buffer; hasContext: () => boolean } {
		const invoice = bob.createInvoice({ description: 'zero-amount' });
		const hashHex = invoice.paymentHash.toString('hex');
		return {
			bolt11: invoice.bolt11,
			paymentHash: invoice.paymentHash,
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			hasContext: () => (alice as any).paymentRetryContexts.has(hashHex)
		};
	}

	/** Fail every HTLC at bob and record the amount of each attempt alice sent. */
	function recordAttemptAmounts(
		alice: LightningNode,
		bob: LightningNode,
		paymentHash: Buffer,
		onAttempt?: () => void
	): bigint[] {
		const amounts: bigint[] = [];
		failEveryHtlcTemporarily(bob, () => {
			amounts.push(alice.getPayment(paymentHash)!.amountMsat);
			onAttempt?.();
		});
		return amounts;
	}

	function refuseEveryAdd(alice: LightningNode): () => void {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const manager = alice.getChannelManager() as any;
		manager.addHtlc = (): ChannelResult => ({
			ok: false,
			actions: [],
			error: 'refused for the test'
		});
		return () => delete manager.addHtlc;
	}

	function throwNoChannelToHop(alice: LightningNode): () => void {
		// A route is found over the graph, then no channel can carry it.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const a = alice as any;
		a.findChannelForPeer = (): null => null;
		a.findLocalChannelByScid = (): null => null;
		return () => {
			delete a.findChannelForPeer;
			delete a.findLocalChannelByScid;
		};
	}

	it('a dispatch that throws drops its context, and a re-send retries at its own amount', () => {
		const { alice, bob } = setupPair(916, 917);
		const invoice = zeroAmountInvoice(alice, bob);

		const restore = throwNoChannelToHop(alice);
		expect(() =>
			alice.sendPaymentWithOptions(invoice.bolt11, EARLIER)
		).to.throw(/No channel to first hop/);
		expect(invoice.hasContext()).to.be.false;
		restore();

		const amounts = recordAttemptAmounts(alice, bob, invoice.paymentHash);
		alice.sendPaymentWithOptions(invoice.bolt11, LATER);

		expect(amounts.length).to.be.greaterThan(1);
		expect(amounts).to.deep.equal(amounts.map(() => LATER.amountMsat));

		alice.destroy();
		bob.destroy();
	});

	it('a dispatch whose HTLC is refused locally drops its context', () => {
		const { alice, bob } = setupPair(918, 919);
		const invoice = zeroAmountInvoice(alice, bob);

		const restore = refuseEveryAdd(alice);
		const refused = alice.sendPaymentWithOptions(invoice.bolt11, EARLIER);
		expect(refused.status).to.equal(PaymentStatus.FAILED);
		expect(invoice.hasContext()).to.be.false;
		restore();

		const amounts = recordAttemptAmounts(alice, bob, invoice.paymentHash);
		alice.sendPaymentWithOptions(invoice.bolt11, LATER);

		expect(amounts.length).to.be.greaterThan(1);
		expect(amounts).to.deep.equal(amounts.map(() => LATER.amountMsat));

		alice.destroy();
		bob.destroy();
	});

	it('a dispatch that throws once its HTLC is out keeps the context', () => {
		const { alice, bob } = setupPair(928, 929);
		const invoice = zeroAmountInvoice(alice, bob);

		// The transport throws as update_add_htlc leaves, after the channel
		// already holds the HTLC.
		let thrown = false;
		alice.prependListener(
			'message:outbound',
			(_pubkey: string, type: number) => {
				if (type !== MessageType.UPDATE_ADD_HTLC || thrown) return;
				thrown = true;
				throw new Error('transport failed');
			}
		);
		expect(() =>
			alice.sendPaymentWithOptions(invoice.bolt11, EARLIER)
		).to.throw(/transport failed/);

		expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(alice.getOutgoingHtlcs(invoice.paymentHash).htlcs).to.have.length(1);
		expect(invoice.hasContext()).to.be.true;

		alice.destroy();
		bob.destroy();
	});

	// Issue #1191: the same throw from an automatic retry.
	it('a retry that throws once its HTLC is out keeps its record and context', () => {
		const { alice, bob } = setupPair(970, 971);
		const invoice = zeroAmountInvoice(alice, bob);
		const attempts = failEveryHtlcTemporarily(bob);

		// bob fails the first attempt. The transport throws as the retry's
		// update_add_htlc leaves, after the channel already holds its HTLC.
		let adds = 0;
		alice.prependListener(
			'message:outbound',
			(_pubkey: string, type: number) => {
				if (type !== MessageType.UPDATE_ADD_HTLC) return;
				if (++adds === 2) throw new Error('transport failed');
			}
		);
		const logs: Array<{ action: string; data: Record<string, unknown> }> = [];
		alice.on('log', (log) => logs.push(log));
		const first = alice.sendPaymentWithOptions(invoice.bolt11, EARLIER);
		expect(attempts()).to.equal(1);
		expect(adds).to.equal(2);

		const live = alice
			.getOutgoingHtlcs(invoice.paymentHash)
			.htlcs.filter((htlc) => !htlc.terminal);
		expect(live).to.have.length(1);
		const record = alice.getPayment(invoice.paymentHash)!;
		expect(record, "the retry's record, not the failed attempt's").to.not.equal(
			first
		);
		expect(record.status).to.equal(PaymentStatus.PENDING);
		expect(record.retryCount).to.equal(1);
		expect(record.sharedSecrets).to.not.equal(first.sharedSecrets);
		expect(
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(alice as any).htlcPaymentMap.get(
				`${live[0].channelId.toString('hex')}:offered-${live[0].htlcId}`
			)
		).to.equal(invoice.paymentHash.toString('hex'));
		expect(invoice.hasContext()).to.be.true;
		expect(
			logs.some(
				(log) =>
					log.action === 'retry_dispatch_threw' &&
					log.data.error === 'transport failed'
			)
		).to.be.true;

		alice.destroy();
		bob.destroy();
	});

	it('a retry refused locally rolls back when the error listener throws', () => {
		const { alice, bob } = setupPair(972, 973);
		const invoice = zeroAmountInvoice(alice, bob);
		const config = alice
			.getChannelManager()
			.listChannels()[0]
			.getFullState().remoteConfig;
		const maxAcceptedHtlcs = config.maxAcceptedHtlcs;
		const attempts = failEveryHtlcTemporarily(bob, (attempt) => {
			if (attempt === 1) config.maxAcceptedHtlcs = 0;
		});
		alice.once('node:error', () => {
			throw new Error('local refusal listener failed');
		});
		const failures: IPaymentInfo[] = [];
		alice.on('payment:failed', (payment) => failures.push(payment));

		const first = alice.sendPaymentWithOptions(invoice.bolt11, EARLIER);
		const record = alice.getPayment(invoice.paymentHash)!;
		expect(attempts()).to.equal(1);
		expect(alice.hasHtlcInFlight(invoice.paymentHash)).to.be.false;
		expect(record).to.equal(first);
		expect(record.status).to.equal(PaymentStatus.FAILED);
		expect(record.retryCount).to.equal(0);
		expect(record.failureCode).to.equal(TEMPORARY_NODE_FAILURE);
		expect(record.failureReason).to.contain('local refusal listener failed');
		expect(failures).to.deep.equal([record]);
		expect(invoice.hasContext()).to.be.false;

		config.maxAcceptedHtlcs = maxAcceptedHtlcs;
		expect(() =>
			alice.sendPaymentWithOptions(invoice.bolt11, LATER)
		).to.not.throw();
		expect(attempts()).to.be.greaterThan(1);

		alice.destroy();
		bob.destroy();
	});

	it("a re-send is not held to a thrown send's CLTV ceiling", () => {
		const { alice, bob } = setupPair(920, 921);
		alice.handleNewBlock(1000);
		bob.handleNewBlock(1000);
		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'ceiling'
		});

		const restore = throwNoChannelToHop(alice);
		expect(() =>
			alice.sendPaymentWithOptions(invoice.bolt11, {
				maxCltvExpiryHeight: 1100
			})
		).to.throw(/No channel to first hop/);
		restore();

		// The earlier ceiling is now below the chain; this send set none.
		alice.handleNewBlock(1200);
		bob.handleNewBlock(1200);
		expect(alice.sendPayment(invoice.bolt11).status).to.equal(
			PaymentStatus.COMPLETED
		);

		alice.destroy();
		bob.destroy();
	});

	it('a context left by a retry refused locally is replaced by the next send', () => {
		const { alice, bob } = setupPair(922, 923);
		const invoice = zeroAmountInvoice(alice, bob);

		// The first attempt reaches bob and fails there. Its retry is refused
		// by addHtlc, so no onion failure ever ends that payment.
		let restore: (() => void) | undefined;
		const amounts = recordAttemptAmounts(
			alice,
			bob,
			invoice.paymentHash,
			() => {
				restore ??= refuseEveryAdd(alice);
			}
		);
		alice.sendPaymentWithOptions(invoice.bolt11, EARLIER);
		expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.FAILED
		);
		expect(amounts).to.deep.equal([EARLIER.amountMsat]);
		expect(invoice.hasContext(), 'precondition: the retry left it').to.be.true;
		restore!();

		amounts.length = 0;
		alice.sendPaymentWithOptions(invoice.bolt11, LATER);

		expect(amounts.length).to.be.greaterThan(1);
		expect(amounts).to.deep.equal(amounts.map(() => LATER.amountMsat));
		expect(alice.getPayment(invoice.paymentHash)!.retryCount).to.equal(
			amounts.length - 1
		);

		alice.destroy();
		bob.destroy();
	});

	it('a re-send from a payment:failed listener is not taken for the retry', () => {
		const { alice, bob } = setupPair(924, 925);
		const invoice = zeroAmountInvoice(alice, bob);

		// The first attempt fails at bob and its retry is refused locally. A
		// listener hears that refusal and re-sends at the later amount.
		let restore: (() => void) | undefined;
		const amounts = recordAttemptAmounts(
			alice,
			bob,
			invoice.paymentHash,
			() => {
				restore ??= refuseEveryAdd(alice);
			}
		);
		alice.once('payment:failed', () => {
			restore!();
			alice.sendPaymentWithOptions(invoice.bolt11, LATER);
		});
		alice.sendPaymentWithOptions(invoice.bolt11, EARLIER);

		expect(amounts.length).to.be.greaterThan(2);
		expect(amounts.slice(1)).to.deep.equal(
			amounts.slice(1).map(() => LATER.amountMsat)
		);

		alice.destroy();
		bob.destroy();
	});

	it("a send refused locally leaves a listener re-send's context alone", () => {
		const { alice, bob } = setupPair(926, 927);
		const invoice = zeroAmountInvoice(alice, bob);
		// bob holds the re-send, so it stays PENDING and keeps its context.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(bob as any).handleFinalHopHtlc = (): void => {};

		const restore = refuseEveryAdd(alice);
		alice.once('payment:failed', () => {
			restore();
			alice.sendPaymentWithOptions(invoice.bolt11, LATER);
		});
		const refused = alice.sendPaymentWithOptions(invoice.bolt11, EARLIER);
		expect(refused.status).to.equal(PaymentStatus.FAILED);

		expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.PENDING
		);
		expect(invoice.hasContext()).to.be.true;

		alice.destroy();
		bob.destroy();
	});
});

describe('Issue #182: failure-embedded channel_update never reaches the graph', () => {
	it('keeps the graph policy when a failure carries a forged channel_update', () => {
		const { alice, bob } = setupPair(920, 921);

		// Install a channel in alice's graph on HER chain (the node is regtest,
		// so setupPair's mainnet-hash announcement never lands in the graph; the
		// direct payments in this file route over local channel edges instead).
		// This is the graph entry a forged update would poison.
		const scid = encodeShortChannelId({
			block: 501,
			txIndex: 1,
			outputIndex: 0
		});
		const apk = Buffer.from(alice.getNodeId(), 'hex');
		const bpk = Buffer.from(bob.getNodeId(), 'hex');
		const aliceIsNode1 = Buffer.compare(apk, bpk) < 0;
		alice.getGraph().addChannelAnnouncement({
			nodeSignature1: Buffer.alloc(64),
			nodeSignature2: Buffer.alloc(64),
			bitcoinSignature1: Buffer.alloc(64),
			bitcoinSignature2: Buffer.alloc(64),
			features: Buffer.alloc(0),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: scid,
			nodeId1: aliceIsNode1 ? apk : bpk,
			nodeId2: aliceIsNode1 ? bpk : apk,
			bitcoinKey1: Buffer.alloc(33, 2),
			bitcoinKey2: Buffer.alloc(33, 3)
		});
		const gossiped: IChannelUpdateMessage = {
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
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
		expect(alice.getGraph().applyChannelUpdate(gossiped), 'baseline update').to
			.be.true;
		expect(
			alice.getGraph().applyChannelUpdate({ ...gossiped, channelFlags: 1 }),
			'baseline update, other direction'
		).to.be.true;

		// Bob answers the HTLC with FEE_INSUFFICIENT whose failure data embeds a
		// channel_update claiming an absurd fee for that channel, strictly newer
		// than the gossiped one. Any hop on a route can forge exactly this:
		// nothing in the failure proves the update describes the channel it
		// claims to. BOLT 4 therefore says the origin MUST NOT apply it to the
		// local network graph.
		const forged: IChannelUpdateMessage = {
			...gossiped,
			timestamp: gossiped.timestamp + 600,
			feeBaseMsat: 999_999,
			feeProportionalMillionths: 999_999
		};
		const forgedBytes = encodeChannelUpdateMessage(forged);
		// fee_insufficient: [u64 htlc_msat][u16 len][channel_update]
		const failureData = Buffer.alloc(10 + forgedBytes.length);
		failureData.writeBigUInt64BE(50_000n, 0);
		failureData.writeUInt16BE(forgedBytes.length, 8);
		forgedBytes.copy(failureData, 10);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const b = bob as any;
		b.handleFinalHopHtlc = (channelId: Buffer, htlcId: bigint): void => {
			const key = `${channelId.toString('hex')}:${htlcId}`;
			const sharedSecret = b.receivedHtlcSharedSecrets.get(key);
			b.channelManager.failHtlc(
				channelId,
				htlcId,
				createFailureMessage(sharedSecret, FEE_INSUFFICIENT, failureData)
			);
		};

		const invoice = bob.createInvoice({
			amountMsat: 50_000n,
			description: 'poison attempt'
		});
		alice.sendPayment(invoice.bolt11);

		// The graph keeps the policy it learned from gossip in setupPair
		// (base 1000, 1 ppm), in both directions.
		const channel = alice.getGraph().getChannel(scid);
		expect(channel, 'channel still in graph').to.not.be.undefined;
		for (const update of [channel!.update1, channel!.update2]) {
			expect(update, 'direction update present').to.not.be.undefined;
			expect(update!.feeBaseMsat, 'gossip fee, not the forged one').to.equal(
				1000
			);
			expect(update!.feeProportionalMillionths).to.equal(1);
		}

		alice.destroy();
		bob.destroy();
	});
});

// ── Issue #1056 ──────────────────────────────────────────────────────────
//
// A three-node line: alice -(local channel)-> bob -(graph channel)-> carol.
// carol issues the invoices, alice pays, and bob's forward handler is
// replaced by what each test scripts: the failure it returns, or a hold.

/** Deliver each node's outbound messages to the other. Once per pair. */
function wire(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === b.getNodeId()) {
			b.handlePeerMessage(a.getNodeId(), type, payload);
		}
	});
	b.on('message:outbound', (pubkey, type, payload) => {
		if (pubkey === a.getNodeId()) {
			a.handlePeerMessage(b.getNodeId(), type, payload);
		}
	});
}

/** Open and confirm funder -> peer, registering its SCID on the funder. */
function openLocalChannel(
	funder: LightningNode,
	peer: LightningNode,
	block: number
): Buffer {
	const channel = funder.openChannel(peer.getNodeId(), 1_000_000n);
	const channelId = funder.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	funder.handleFundingConfirmed(channelId);
	peer.handleFundingConfirmed(channelId);
	const scid = encodeShortChannelId({ block, txIndex: 1, outputIndex: 0 });
	funder.registerChannelScid(channelId, scid);
	return scid;
}

type Policy = Pick<
	IChannelUpdateMessage,
	| 'cltvExpiryDelta'
	| 'htlcMinimumMsat'
	| 'feeBaseMsat'
	| 'feeProportionalMillionths'
>;

/**
 * Put a channel between a and b in `node`'s graph on its own chain, a's
 * policy on a's side and b's on b's. Returns the update on a's side.
 */
function announceGraphChannel(
	node: LightningNode,
	scid: Buffer,
	a: Buffer,
	b: Buffer,
	policyA: Policy,
	policyB: Policy
): IChannelUpdateMessage {
	const aIsNode1 = Buffer.compare(a, b) < 0;
	node.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aIsNode1 ? a : b,
		nodeId2: aIsNode1 ? b : a,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	const base = {
		signature: Buffer.alloc(64),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	const sideA: IChannelUpdateMessage = {
		...base,
		channelFlags: aIsNode1 ? 0 : 1,
		...policyA
	};
	const sideB: IChannelUpdateMessage = {
		...base,
		channelFlags: aIsNode1 ? 1 : 0,
		...policyB
	};
	expect(node.getGraph().applyChannelUpdate(sideA), 'graph update, a side').to
		.be.true;
	expect(node.getGraph().applyChannelUpdate(sideB), 'graph update, b side').to
		.be.true;
	return sideA;
}

/** `msg` encoded with a signature by `privkey` in place of its own. */
function signedUpdate(msg: IChannelUpdateMessage, privkey: Buffer): Buffer {
	const unsigned = encodeChannelUpdateMessage({
		...msg,
		signature: Buffer.alloc(64)
	});
	return encodeChannelUpdateMessage({
		...msg,
		signature: signChannelUpdate(unsigned, privkey)
	});
}

/**
 * Failure data embedding a channel_update, in the BOLT 4 layout of `code`:
 * [u64 htlc_msat] for fee_insufficient and amount_below_minimum, [u32
 * cltv_expiry] for incorrect_cltv_expiry, then [u16 len][channel_update].
 */
function failureDataWithUpdate(code: number, update: Buffer): Buffer {
	const prefix = code === INCORRECT_CLTV_EXPIRY ? 4 : 8;
	const data = Buffer.alloc(prefix + 2 + update.length);
	if (prefix === 8) data.writeBigUInt64BE(50_000n, 0);
	else data.writeUInt32BE(500, 0);
	data.writeUInt16BE(update.length, prefix);
	update.copy(data, prefix + 2);
	return data;
}

interface IForwardAttempt {
	attempt: number;
	sharedSecret: Buffer;
	fail: (reason: Buffer) => void;
}

/**
 * Replace `node`'s forwarding with `handler`, which either fails the HTLC
 * with the reason bytes it chooses or holds it by doing nothing. Returns
 * the attempt counter.
 */
function interceptForward(
	node: LightningNode,
	handler: (attempt: IForwardAttempt) => void
): () => number {
	let attempts = 0;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const n = node as any;
	n.handleForwardHtlc = (
		inChannelId: Buffer,
		inHtlcId: bigint,
		_hash: Buffer,
		processed: { sharedSecret: Buffer }
	): void => {
		attempts++;
		handler({
			attempt: attempts,
			sharedSecret: processed.sharedSecret,
			fail: (reason: Buffer) =>
				n.channelManager.failHtlc(inChannelId, inHtlcId, reason)
		});
	};
	return () => attempts;
}

const BOB_POLICY: Policy = {
	cltvExpiryDelta: 40,
	htlcMinimumMsat: 1000n,
	feeBaseMsat: 1000,
	feeProportionalMillionths: 100
};
const CAROL_POLICY: Policy = {
	cltvExpiryDelta: 40,
	htlcMinimumMsat: 1000n,
	feeBaseMsat: 1000,
	feeProportionalMillionths: 1
};
const AMOUNT_MSAT = 50_000n;

interface ITriple {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	aliceBobScid: Buffer;
	bobCarolScid: Buffer;
	/** bob's graph policy on the bob -> carol channel. */
	bobSide: IChannelUpdateMessage;
	bobPrivkey: Buffer;
	destroy: () => void;
}

function setupTriple(seed: number): ITriple {
	const alice = createNode(seed);
	const bob = createNode(seed + 1);
	const carol = createNode(seed + 2);
	wire(alice, bob);
	const aliceBobScid = openLocalChannel(alice, bob, 500);
	const bobCarolScid = encodeShortChannelId({
		block: 600,
		txIndex: 1,
		outputIndex: 0
	});
	const bobSide = announceGraphChannel(
		alice,
		bobCarolScid,
		Buffer.from(bob.getNodeId(), 'hex'),
		Buffer.from(carol.getNodeId(), 'hex'),
		BOB_POLICY,
		CAROL_POLICY
	);
	return {
		alice,
		bob,
		carol,
		aliceBobScid,
		bobCarolScid,
		bobSide,
		bobPrivkey: makeNodeConfig(seed + 1).nodePrivateKey,
		destroy: (): void => {
			alice.destroy();
			bob.destroy();
			carol.destroy();
		}
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const internals = (node: LightningNode): any => node as any;

const penaltyOn = (node: LightningNode, scid: Buffer): bigint =>
	internals(node).missionControl.getPenalty(scid.toString('hex'));

/** bob's stored policy on the bob -> carol channel, as alice's graph holds it. */
function storedBobSide(t: ITriple): IChannelUpdateMessage {
	const channel = t.alice.getGraph().getChannel(t.bobCarolScid)!;
	const bobIsNode1 = (t.bobSide.channelFlags & 1) === 0;
	return (bobIsNode1 ? channel.update1 : channel.update2)!;
}

describe('Issue #1056: a policy failure re-prices its hop from the update it carries', () => {
	/**
	 * bob answers the first attempt with `code` carrying `update`, then holds
	 * every later attempt. Returns the attempt counter and the record.
	 */
	function payWithFirstFailure(
		t: ITriple,
		code: number,
		update: Buffer,
		description: string
	): { attempts: () => number; record: () => IPaymentInfo } {
		const attempts = interceptForward(
			t.bob,
			({ attempt, sharedSecret, fail }) => {
				if (attempt === 1) {
					fail(
						createFailureMessage(
							sharedSecret,
							code,
							failureDataWithUpdate(code, update)
						)
					);
				}
			}
		);
		const invoice = t.carol.createInvoice({
			amountMsat: AMOUNT_MSAT,
			description
		});
		const sent = t.alice.sendPayment(invoice.bolt11);
		return {
			attempts,
			record: () => t.alice.getPayment(sent.paymentHash)!
		};
	}
	it('fee_insufficient with a valid signed update: the retry takes the same channel at the new fee, the graph keeps its policy, and the override does not leak', () => {
		const t = setupTriple(930);
		const logs: Array<{ category: string; action: string; data: any }> = []; // eslint-disable-line @typescript-eslint/no-explicit-any
		t.alice.on('log', (log) => logs.push(log));
		const repriced: IChannelUpdateMessage = {
			...t.bobSide,
			timestamp: t.bobSide.timestamp + 60,
			feeBaseMsat: 3000
		};
		const { attempts, record } = payWithFirstFailure(
			t,
			FEE_INSUFFICIENT,
			signedUpdate(repriced, t.bobPrivkey),
			'reprice'
		);

		// Before the fix the channel was excluded instead and the retry found
		// no route: one attempt, then FAILED.
		expect(attempts(), 'the retry was dispatched').to.equal(2);
		const retried = record();
		expect(retried.status).to.equal(PaymentStatus.PENDING);
		expect(retried.retryCount).to.equal(1);
		expect(
			retried.route!.hops[1].shortChannelId.equals(t.bobCarolScid),
			'the retry routes over the re-priced channel'
		).to.be.true;
		expect(
			retried.route!.totalFeeMsat,
			'at the fee the failure announced'
		).to.equal(calculateFee(AMOUNT_MSAT, 3000, 100));

		// Issue #182: the graph still holds what gossip said.
		expect(storedBobSide(t).feeBaseMsat).to.equal(1000);
		// A re-priced hop is not an unreliable one.
		expect(penaltyOn(t.alice, t.bobCarolScid)).to.equal(0n);
		expect(
			logs.some(
				(log) =>
					log.category === 'payment' &&
					log.action === 'retry_repriced' &&
					log.data.feeBaseMsat === 3000 &&
					log.data.shortChannelId === t.bobCarolScid.toString('hex')
			),
			'the re-price is logged with the update fields'
		).to.be.true;

		// The override belongs to that payment: another one to the same
		// destination routes at the graph's price.
		const other = t.alice.sendPayment(
			t.carol.createInvoice({ amountMsat: AMOUNT_MSAT, description: 'other' })
				.bolt11
		);
		expect(attempts()).to.equal(3);
		expect(other.route!.totalFeeMsat).to.equal(
			calculateFee(AMOUNT_MSAT, 1000, 100)
		);
		t.destroy();
	});

	it('an update with a bad signature keeps the exclusion', () => {
		const t = setupTriple(933);
		const forged = signedUpdate(
			{ ...t.bobSide, feeBaseMsat: 3000 },
			crypto.createHash('sha256').update('not bob').digest()
		);
		const { attempts, record } = payWithFirstFailure(
			t,
			FEE_INSUFFICIENT,
			forged,
			'bad sig'
		);
		expect(attempts()).to.equal(1);
		expect(record().status).to.equal(PaymentStatus.FAILED);
		expect(record().failureReason).to.contain('No route found');
		expect(Number(penaltyOn(t.alice, t.bobCarolScid))).to.be.above(0);
		t.destroy();
	});

	it('an update naming another channel keeps the exclusion', () => {
		const t = setupTriple(936);
		const elsewhere = signedUpdate(
			{
				...t.bobSide,
				feeBaseMsat: 3000,
				shortChannelId: encodeShortChannelId({
					block: 601,
					txIndex: 1,
					outputIndex: 0
				})
			},
			t.bobPrivkey
		);
		const { attempts, record } = payWithFirstFailure(
			t,
			FEE_INSUFFICIENT,
			elsewhere,
			'other scid'
		);
		expect(attempts()).to.equal(1);
		expect(record().status).to.equal(PaymentStatus.FAILED);
		expect(record().failureReason).to.contain('No route found');
		t.destroy();
	});

	it("an update for the other side of the channel (carol's direction) keeps the exclusion", () => {
		const t = setupTriple(939);
		const wrongSide = signedUpdate(
			{
				...t.bobSide,
				feeBaseMsat: 3000,
				channelFlags: t.bobSide.channelFlags ^ 1
			},
			t.bobPrivkey
		);
		const { attempts, record } = payWithFirstFailure(
			t,
			FEE_INSUFFICIENT,
			wrongSide,
			'wrong side'
		);
		expect(attempts()).to.equal(1);
		expect(record().status).to.equal(PaymentStatus.FAILED);
		expect(record().failureReason).to.contain('No route found');
		t.destroy();
	});

	it('an update repeating the policy we routed with is not a re-price: the exclusion stays', () => {
		// A node refusing the fee it advertises (an inbound fee we cannot
		// see, say) would refuse the retry too, so it is routed around.
		const t = setupTriple(942);
		const same = signedUpdate(
			{ ...t.bobSide, timestamp: t.bobSide.timestamp + 60 },
			t.bobPrivkey
		);
		const { attempts, record } = payWithFirstFailure(
			t,
			FEE_INSUFFICIENT,
			same,
			'same policy'
		);
		expect(attempts()).to.equal(1);
		expect(record().status).to.equal(PaymentStatus.FAILED);
		expect(record().failureReason).to.contain('No route found');
		t.destroy();
	});

	it('incorrect_cltv_expiry with an update re-prices the delta the same way', () => {
		const t = setupTriple(945);
		const longer = signedUpdate(
			{ ...t.bobSide, cltvExpiryDelta: 144 },
			t.bobPrivkey
		);
		const { attempts, record } = payWithFirstFailure(
			t,
			INCORRECT_CLTV_EXPIRY,
			longer,
			'cltv'
		);
		expect(attempts()).to.equal(2);
		const retried = record();
		expect(retried.status).to.equal(PaymentStatus.PENDING);
		expect(retried.route!.hops[1].shortChannelId.equals(t.bobCarolScid)).to.be
			.true;
		// hops[i].cltvExpiryDelta is the delta on the channel INTO hop i,
		// which bob charges.
		expect(retried.route!.hops[1].cltvExpiryDelta).to.equal(144);
		expect(retried.route!.totalFeeMsat).to.equal(
			calculateFee(AMOUNT_MSAT, 1000, 100)
		);
		expect(storedBobSide(t).cltvExpiryDelta).to.equal(40);
		t.destroy();
	});

	it('amount_below_minimum with an update re-prices the same way', () => {
		const t = setupTriple(948);
		const stricter = signedUpdate(
			{ ...t.bobSide, htlcMinimumMsat: 10_000n, feeBaseMsat: 2000 },
			t.bobPrivkey
		);
		const { attempts, record } = payWithFirstFailure(
			t,
			AMOUNT_BELOW_MINIMUM,
			stricter,
			'minimum'
		);
		expect(attempts()).to.equal(2);
		const retried = record();
		expect(retried.status).to.equal(PaymentStatus.PENDING);
		expect(retried.route!.hops[1].shortChannelId.equals(t.bobCarolScid)).to.be
			.true;
		expect(retried.route!.totalFeeMsat).to.equal(
			calculateFee(AMOUNT_MSAT, 2000, 100)
		);
		expect(storedBobSide(t).htlcMinimumMsat).to.equal(1000n);
		t.destroy();
	});
});

describe('Issue #1056: first-hop diversification', () => {
	/** A temporary failure from carol (hop index 1), relayed by bob. */
	function carolFailure(alice: LightningNode, bobSecret: Buffer): Buffer {
		const pending = alice
			.listPayments()
			.find((p) => p.status === PaymentStatus.PENDING)!;
		return wrapFailureMessage(
			bobSecret,
			createFailureMessage(pending.sharedSecrets![1], TEMPORARY_NODE_FAILURE)
		);
	}

	it('one usable channel and a failure at hop 2: no retry excludes that channel, every retry is dispatched', () => {
		const t = setupTriple(950);
		const attempts = interceptForward(t.bob, ({ sharedSecret, fail }) =>
			fail(carolFailure(t.alice, sharedSecret))
		);
		const sent = t.alice.sendPayment(
			t.carol.createInvoice({ amountMsat: AMOUNT_MSAT, description: 'hop 2' })
				.bolt11
		);
		// One attempt plus the three retries. Before the fix the second retry
		// excluded alice's only channel and died with NO_ROUTE after two.
		expect(attempts()).to.equal(4);
		const record = t.alice.getPayment(sent.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.FAILED);
		expect(record.failureSourceIndex).to.equal(1);
		expect(record.retryCount).to.equal(3);
		expect(record.failureReason ?? '').to.not.contain('retry not dispatched');
		t.destroy();
	});

	it('one usable channel and a failure at hop 0: the channel is kept, and why is logged', () => {
		const t = setupTriple(953);
		const logs: Array<{ category: string; action: string }> = [];
		t.alice.on('log', (log) => logs.push(log));
		const attempts = interceptForward(t.bob, ({ sharedSecret, fail }) =>
			fail(createFailureMessage(sharedSecret, TEMPORARY_NODE_FAILURE))
		);
		const sent = t.alice.sendPayment(
			t.carol.createInvoice({ amountMsat: AMOUNT_MSAT, description: 'hop 0' })
				.bolt11
		);
		expect(attempts()).to.equal(4);
		const record = t.alice.getPayment(sent.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.FAILED);
		expect(record.failureReason ?? '').to.not.contain('retry not dispatched');
		expect(
			logs.some(
				(log) => log.category === 'payment' && log.action === 'first_hop_kept'
			)
		).to.be.true;
		t.destroy();
	});

	/**
	 * alice with channels to bob AND to bob2, both of which reach carol; the
	 * bob route is cheaper, so the first attempts go that way.
	 */
	function setupFork(seed: number): ITriple & { bob2: LightningNode } {
		const t = setupTriple(seed);
		const bob2 = createNode(seed + 3);
		wire(t.alice, bob2);
		openLocalChannel(t.alice, bob2, 502);
		announceGraphChannel(
			t.alice,
			encodeShortChannelId({ block: 602, txIndex: 1, outputIndex: 0 }),
			Buffer.from(bob2.getNodeId(), 'hex'),
			Buffer.from(t.carol.getNodeId(), 'hex'),
			{ ...BOB_POLICY, feeBaseMsat: 5000 },
			CAROL_POLICY
		);
		const destroy = t.destroy;
		return {
			...t,
			bob2,
			destroy: (): void => {
				destroy();
				bob2.destroy();
			}
		};
	}

	it('two usable channels and failures at hop 0: the second retry diversifies to the other channel', () => {
		const t = setupFork(956);
		const bobAttempts = interceptForward(t.bob, ({ sharedSecret, fail }) =>
			fail(createFailureMessage(sharedSecret, TEMPORARY_NODE_FAILURE))
		);
		const bob2Attempts = interceptForward(t.bob2, () => {});
		const sent = t.alice.sendPayment(
			t.carol.createInvoice({ amountMsat: AMOUNT_MSAT, description: 'fork' })
				.bolt11
		);
		expect(bobAttempts()).to.equal(2);
		expect(bob2Attempts()).to.equal(1);
		const record = t.alice.getPayment(sent.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.PENDING);
		expect(record.route!.hops[0].pubkey.toString('hex')).to.equal(
			t.bob2.getNodeId()
		);
		t.destroy();
	});

	it('two usable channels and an undecryptable failure: the second retry diversifies as well', () => {
		const t = setupFork(960);
		const bobAttempts = interceptForward(
			t.bob,
			({ attempt, sharedSecret, fail }) =>
				fail(
					attempt === 1
						? createFailureMessage(sharedSecret, TEMPORARY_NODE_FAILURE)
						: crypto.randomBytes(292)
				)
		);
		const bob2Attempts = interceptForward(t.bob2, () => {});
		const sent = t.alice.sendPayment(
			t.carol.createInvoice({ amountMsat: AMOUNT_MSAT, description: 'garbage' })
				.bolt11
		);
		expect(bobAttempts()).to.equal(2);
		expect(bob2Attempts()).to.equal(1);
		const record = t.alice.getPayment(sent.paymentHash)!;
		expect(record.status).to.equal(PaymentStatus.PENDING);
		expect(record.route!.hops[0].pubkey.toString('hex')).to.equal(
			t.bob2.getNodeId()
		);
		t.destroy();
	});

	it('two usable channels and a failure at hop 2: the first hop is kept', () => {
		const t = setupFork(964);
		const bobAttempts = interceptForward(t.bob, ({ sharedSecret, fail }) =>
			fail(carolFailure(t.alice, sharedSecret))
		);
		const bob2Attempts = interceptForward(t.bob2, () => {});
		t.alice.sendPayment(
			t.carol.createInvoice({ amountMsat: AMOUNT_MSAT, description: 'keep' })
				.bolt11
		);
		expect(bobAttempts()).to.equal(4);
		expect(bob2Attempts()).to.equal(0);
		t.destroy();
	});
});
