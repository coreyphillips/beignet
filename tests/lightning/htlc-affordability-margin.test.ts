/**
 * Issue #193: an HTLC offered at the sender's exact spendable ceiling must
 * always be accepted by the receiver's affordability check.
 *
 * Live incident: a 10,001-sat payment at exactly getSpendableOutboundMsat()
 * force-closed a healthy channel between two beignet 0.7.0 nodes whose books
 * agreed to the satoshi. The sender priced its retained commitment fee at the
 * live feerate; the receiver priced its demand at the static open-time
 * localConfig.feeratePerKw and counted active HTLCs from its own book. At the
 * boundary, a sats-scale formula disagreement becomes a protocol violation
 * the receiver MUST fail the channel over (BOLT 2).
 *
 * Two-part fix under test: the receiver now prices at the live commitment
 * feerate (same source as the sender), and the sender retains an LND-style
 * fee-spike buffer (commitment fee at twice the live rate with one extra
 * HTLC slot), so an offer at the ceiling always clears the receiver's margin.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`affordability-seed-${id}`))
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

function makeNodeConfig(
	seedId: number,
	extra: Partial<INodeConfig> = {}
): INodeConfig {
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
			.digest(),
		// Secret behind makeBasepoints' htlcBasepoint (keys[4]): without it the
		// per-HTLC signatures in commitment_signed are made with a fallback key
		// and the peer rejects them ('Invalid HTLC signature').
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		...extra
	};
}

function createNode(
	seedId: number,
	extra: Partial<INodeConfig> = {}
): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, extra));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function wire(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId()) {
			b.handlePeerMessage(a.getNodeId(), type, payload);
		}
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId()) {
			a.handlePeerMessage(b.getNodeId(), type, payload);
		}
	});
}

function openChannel(alice: LightningNode, bob: LightningNode): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

/**
 * Pay bob an invoice for EXACTLY alice's spendable ceiling and report how it
 * went, plus whether the receiver's affordability guard fired.
 */
function payAtCeiling(
	alice: LightningNode,
	bob: LightningNode,
	channelId: Buffer
): { status: PaymentStatus | undefined; affordabilityErrors: string[] } {
	const affordabilityErrors: string[] = [];
	for (const n of [alice, bob]) {
		n.on('node:error', (e: { message?: string }) => {
			if (/cannot afford/i.test(e.message ?? '')) {
				affordabilityErrors.push(e.message!);
			}
		});
	}
	const ceiling = alice
		.getChannelManager()
		.getChannel(channelId)!
		.getSpendableOutboundMsat();
	expect(ceiling > 0n, 'ceiling positive').to.equal(true);

	const invoice = bob.createInvoice({
		amountMsat: ceiling,
		description: 'exact ceiling'
	});
	const sent = alice.sendPayment(invoice.bolt11);
	const record = alice
		.listPayments()
		.find((p) => p.paymentHash.equals(sent.paymentHash));
	return { status: record?.status, affordabilityErrors };
}

describe('Issue #193: HTLCs at the spendable ceiling never trip the receiver', function () {
	this.timeout(10_000);

	let alice: LightningNode;
	let bob: LightningNode;

	afterEach(function () {
		alice.destroy();
		bob.destroy();
	});

	it('a payment of exactly the spendable ceiling completes (symmetric configs)', function () {
		alice = createNode(1);
		bob = createNode(2);
		wire(alice, bob);
		const channelId = openChannel(alice, bob);

		const { status, affordabilityErrors } = payAtCeiling(alice, bob, channelId);
		expect(affordabilityErrors, 'no affordability refusal').to.deep.equal([]);
		expect(status).to.equal(PaymentStatus.COMPLETED);
	});

	it('a ceiling payment survives a receiver whose CONFIG feerate drifted high', function () {
		// The incident shape: the receiver used to price its demand at the
		// static localConfig.feeratePerKw. A receiver whose config carries a
		// higher rate than the live commitment feerate then demands more
		// retained fee than the sender's live-rate arithmetic keeps back, and
		// a boundary HTLC fails the channel between two honest nodes. The
		// receiver must price at the live rate; the sender's buffer covers the
		// remaining count-delta noise.
		alice = createNode(3);
		bob = createNode(4, {
			channelConfig: { ...DEFAULT_CHANNEL_CONFIG, feeratePerKw: 2500 }
		});
		wire(alice, bob);
		const channelId = openChannel(alice, bob);

		const { status, affordabilityErrors } = payAtCeiling(alice, bob, channelId);
		expect(
			affordabilityErrors,
			'receiver must not refuse a ceiling offer over its config rate'
		).to.deep.equal([]);
		expect(status).to.equal(PaymentStatus.COMPLETED);
	});

	it('the funder retains a fee-spike buffer above the single-fee ceiling', function () {
		alice = createNode(5);
		bob = createNode(6);
		wire(alice, bob);
		const channelId = openChannel(alice, bob);

		const channel = alice.getChannelManager().getChannel(channelId)!;
		const state = channel.getFullState();
		const reserveMsat = state.remoteConfig.channelReserveSatoshis * 1000n;
		const spendable = channel.getSpendableOutboundMsat();

		// Strictly below balance minus reserve: the buffer holds back real
		// margin, not just the one-commitment fee the old formula kept.
		const singleFeeCeiling = state.localBalanceMsat - reserveMsat;
		expect(spendable < singleFeeCeiling, 'buffer applied').to.equal(true);
		// And the margin exceeds what a SINGLE commitment fee explains: at the
		// default 253 sat/kw a one-HTLC non-anchor commitment costs ~326 sats,
		// which is all the old formula retained. The 2x-rate, extra-slot buffer
		// must hold back meaningfully more.
		expect(
			singleFeeCeiling - spendable > 400_000n, // > 400 sats
			'margin beyond a single commitment fee'
		).to.equal(true);
	});
});
