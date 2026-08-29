/**
 * The two halves of direct funding against each other, in one process (issue
 * #613 over #612).
 *
 * Both engines are real: the payer selects a real coin, seals real frames over
 * the real direct-peer lane, and verifies a sign request the real receiver
 * built and attested with a real node key. What is stubbed is the channel, and
 * only the channel: `FakeDfNode` stands in for the interactive transaction
 * exchange the receiver drives, because that machinery has suites of its own.
 *
 * This is the in-process half of the regtest matrix the issue asks for: new
 * channel and splice, anonymous and paired. It cannot prove a transaction
 * broadcasts; it does prove that what one side builds is what the other side
 * accepts, byte for byte, which is the half a regtest run cannot isolate.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { signMessageWithKey } from '../../src/lightning/crypto/message-signing';
import { createFundingScript } from '../../src/lightning/script/funding';
import {
	encodeRequestEnvelope,
	mintRequestEnvelope
} from '../../src/lightning/direct-funding/envelope';
import { requestEncryptionPublicKey } from '../../src/lightning/direct-funding/requests';
import {
	chainHashForNetwork,
	DfTransportType,
	IDfRequestRecord
} from '../../src/lightning/direct-funding/types';
import { IDfOffer } from '../../src/lightning/direct-funding/messages';
import { DirectFundingReceiver } from '../../src/lightning/direct-funding/receiver/engine';
import { DirectFundingSender } from '../../src/lightning/direct-funding/sender/engine';
import { DirectFundingPaymentStore } from '../../src/lightning/direct-funding/sender/records';
import { DfTransportRegistry } from '../../src/lightning/direct-funding/transport/registry';
import { DfDirectPeerLaneFactory } from '../../src/lightning/direct-funding/transport/direct-peer';
import { Network } from '../../src/lightning/invoice/types';
import {
	FakeDfNode,
	flush,
	LSP_PUBKEY,
	memoryStorage as receiverStorage
} from './helpers/df-receiver';
import {
	FakeSenderWallet,
	ITestCoin,
	makeCoin,
	memoryStorage
} from './helpers/df-sender';
import { FakeDfNetwork, FakeDfPeer } from './helpers/df-transport';

const AMOUNT = 100_000n;
const FEE_CEILING = 2_000n;

/**
 * A receiver stub that signs its attestation with a real node key, and with
 * the key its PEER identity uses: the payer dials the node the envelope names,
 * so the two have to be the same key.
 */
class SigningDfNode extends FakeDfNode {
	readonly nodeId: Buffer;

	constructor(
		storage: ConstructorParameters<typeof FakeDfNode>[0],
		readonly nodePrivkey: Buffer
	) {
		super(storage);
		this.nodeId = getPublicKey(nodePrivkey);
	}

	signMessage(message?: string): string {
		return signMessageWithKey(message ?? '', this.nodePrivkey);
	}
}

interface IEndToEnd {
	node: SigningDfNode;
	receiver: DirectFundingReceiver;
	sender: DirectFundingSender;
	record: IDfRequestRecord;
	request: string;
	coin: ITestCoin;
	wallet: FakeSenderWallet;
	payments: DirectFundingPaymentStore;
	payerId: string;
	fundingScript: Buffer;
	/** The offer the payer will make, rebuilt from what it was given. */
	expectedOffer(): IDfOffer;
	stop(): void;
}

async function setup(
	opts: {
		paired?: boolean;
		allowSplice?: boolean;
		allowZeroConf?: boolean;
		amountSat?: bigint;
	} = {}
): Promise<IEndToEnd> {
	const net = new FakeDfNetwork();
	const payerPeer: FakeDfPeer = net.add('df-e2e-payer');
	const receiverPeer: FakeDfPeer = net.add('df-e2e-receiver');
	net.connect(payerPeer, receiverPeer);

	const node = new SigningDfNode(receiverStorage(), receiverPeer.privkey);
	const record = node.mintRequest(
		3_600_000,
		opts.amountSat === undefined ? undefined : opts.amountSat
	);
	const request = encodeRequestEnvelope(
		mintRequestEnvelope(
			{
				requestId: Buffer.from(record.requestId, 'hex'),
				chainHash: chainHashForNetwork(Network.REGTEST),
				receiverNodeId: node.nodeId,
				expiresAt: record.expiresAt,
				...(opts.amountSat !== undefined ? { amountSat: opts.amountSat } : {}),
				receiptHash: Buffer.from(record.receiptHash, 'hex'),
				encryptionKey: requestEncryptionPublicKey(record),
				transports: [
					{
						type: DfTransportType.DIRECT_PEER,
						host: '127.0.0.1',
						port: 9735
					}
				]
			},
			(message) => node.signMessage(message)
		)
	);

	// The coin the payer will offer, published so the receiver's own chain
	// source can resolve it: nothing here takes the payer's word for it.
	const coin = makeCoin(300_000);
	node.publish(coin);
	if (opts.paired) node.trustedPayers.add(payerPeer.id);
	// Upstream's own gate, which the receiver ANDs with its own switch.
	node.zeroConfPeers.add(LSP_PUBKEY);

	const receiver = new DirectFundingReceiver(node, {
		allowSplice: opts.allowSplice === true,
		allowZeroConf: opts.allowZeroConf === true
	});
	receiver.start();
	const receiverRegistry = new DfTransportRegistry();
	const receiverFactory = new DfDirectPeerLaneFactory(receiverPeer);
	receiverRegistry.register({
		type: DfTransportType.DIRECT_PEER,
		enabled: true,
		load: () => receiverFactory
	});
	await receiver.attach(receiverRegistry);

	const payerRegistry = new DfTransportRegistry();
	const payerFactory = new DfDirectPeerLaneFactory(payerPeer);
	payerRegistry.register({
		type: DfTransportType.DIRECT_PEER,
		enabled: true,
		load: () => payerFactory
	});
	const wallet = new FakeSenderWallet([coin]);
	const payments = new DirectFundingPaymentStore({ storage: memoryStorage() });
	const sender = new DirectFundingSender(
		{
			wallet,
			registry: payerRegistry,
			payments,
			chainHash: (): Buffer => chainHashForNetwork(Network.REGTEST)
		},
		{ offerResendDelaysMs: [], offerTimeoutMs: 4_000, receiptTimeoutMs: 500 }
	);

	const pubkeys = node.fundingPubkeys()!;
	return {
		node,
		receiver,
		sender,
		record,
		request,
		coin,
		wallet,
		payments,
		payerId: payerPeer.id,
		fundingScript: createFundingScript(pubkeys.local, pubkeys.remote)
			.p2wshOutput,
		expectedOffer: (): IDfOffer => ({
			offerId: Buffer.alloc(16),
			amountSat: opts.amountSat ?? AMOUNT,
			txid: Buffer.from(coin.txidHex, 'hex'),
			vout: coin.vout,
			valueSat: coin.valueSat,
			sequence: 0xfffffffd,
			changeScript: wallet.changeScript_,
			maxTotalFeeSat: FEE_CEILING,
			receiptHash: Buffer.from(record.receiptHash, 'hex'),
			ownership: { pubkey: coin.pubkey, signature: Buffer.alloc(64) }
		}),
		stop: (): void => {
			receiver.stop();
			receiverFactory.destroy();
			payerFactory.destroy();
		}
	};
}

describe('Direct funding end to end: payer against receiver', () => {
	it('funds a new channel: one exchange, one spend, a verified receipt', async () => {
		const e2e = await setup();
		try {
			const send = e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			// The receiver admits the offer and starts the open; standing in for
			// the interactive transaction, we hand it the negotiated bytes.
			await flush(8);
			expect(
				e2e.node.opens,
				'the receiver never started an open'
			).to.have.length(1);
			expect(e2e.node.opens[0].params.fundingSatoshis).to.equal(AMOUNT);
			e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
				fundingScript: e2e.fundingScript
			});
			const result = await send;

			expect(
				result.attested,
				'the payer did not verify the attestation'
			).to.equal(true);
			expect(result.status).to.equal('SIGNED_PENDING');
			// The receipt is the receiver's proof of delivery, and it opens the
			// hash the request was minted with.
			expect(result.receiptPreimageHex).to.equal(e2e.record.preimageHex);
			expect(
				crypto
					.createHash('sha256')
					.update(Buffer.from(result.receiptPreimageHex!, 'hex'))
					.digest('hex')
			).to.equal(e2e.record.receiptHash);
			// One witness, delivered to the channel, for the coin the payer offered.
			expect(e2e.node.witnesses).to.have.length(1);
			expect(e2e.node.witnesses[0].kind).to.equal('open');
			expect(result.spentTxid).to.equal(e2e.coin.txidHex);
			// And the payer holds the coin against its own selection from here.
			expect(e2e.wallet.listSpendable()).to.deep.equal([]);
		} finally {
			e2e.stop();
		}
	});

	it('only a paired payer buys zero-conf, and only with consent', async () => {
		// The matrix cell that decides who takes the double-spend risk. Pairing
		// comes off the LANE (the direct-peer connection is the only one that
		// authenticates a payer), and it is necessary, not sufficient: the
		// operator has to have said yes to zero-conf direct funding as well.
		for (const [paired, allowZeroConf, expected] of [
			[false, true, undefined],
			[true, false, undefined],
			[true, true, true]
		] as Array<[boolean, boolean, true | undefined]>) {
			const e2e = await setup({ paired, allowZeroConf });
			try {
				const send = e2e.sender.send(e2e.request, {
					amountSat: AMOUNT,
					maxTotalFeeSat: FEE_CEILING
				});
				await flush(8);
				const label = `paired=${paired} allowZeroConf=${allowZeroConf}`;
				expect(e2e.node.opens[0].params.trusted, label).to.equal(expected);
				e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
					fundingScript: e2e.fundingScript
				});
				const result = await send;
				expect(result.attested, label).to.equal(true);
			} finally {
				e2e.stop();
			}
		}
	});

	it('splices an existing channel when the payer is paired and splice is on', async () => {
		const e2e = await setup({ paired: true, allowSplice: true });
		e2e.node.spliceChannel = Buffer.alloc(32, 9);
		try {
			const send = e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			await flush(8);
			expect(
				e2e.node.splices,
				'the receiver opened instead of splicing'
			).to.have.length(1);
			expect(e2e.node.opens).to.have.length(0);
			// The new funding output carries the pre-splice capacity as well, which
			// is the arm the payer checks the shared input for.
			e2e.node.completeSpliceNegotiation(
				e2e.coin,
				e2e.expectedOffer(),
				500_000n,
				{ fundingScript: e2e.fundingScript }
			);
			const result = await send;
			expect(result.attested).to.equal(true);
			expect(e2e.node.witnesses[0].kind).to.equal('splice');
			expect(result.receiptPreimageHex).to.equal(e2e.record.preimageHex);
		} finally {
			e2e.stop();
		}
	});

	it('honours a request that fixed its amount, on both sides', async () => {
		const e2e = await setup({ amountSat: 75_000n });
		try {
			// The payer names no amount: the envelope's is the one that binds, and
			// the receiver checks it against its OWN record rather than the offer.
			const send = e2e.sender.send(e2e.request, {
				maxTotalFeeSat: FEE_CEILING
			});
			await flush(8);
			expect(e2e.node.opens[0].params.fundingSatoshis).to.equal(75_000n);
			e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
				fundingScript: e2e.fundingScript
			});
			const result = await send;
			expect(result.amountSat).to.equal(75_000);
			expect(result.attested).to.equal(true);
		} finally {
			e2e.stop();
		}
	});

	it('a decline reaches the payer as a refusal, with nothing spent', async () => {
		const e2e = await setup();
		e2e.node.lspPubkey = null;
		try {
			let error: unknown = null;
			try {
				await e2e.sender.send(e2e.request, {
					amountSat: AMOUNT,
					maxTotalFeeSat: FEE_CEILING
				});
			} catch (err) {
				error = err;
			}
			expect((error as { code?: string })?.code).to.equal('OFFER_DECLINED');
			expect((error as Error).message).to.contain('no liquidity peer');
			expect(e2e.node.opens).to.have.length(0);
			expect(
				e2e.wallet.frozen.size,
				'a declined offer reserved a coin'
			).to.equal(0);
			expect(e2e.payments.list()[0].status).to.equal('ABORTED');
		} finally {
			e2e.stop();
		}
	});

	it('a duplicate offer is replayed, and funds nothing twice', async () => {
		const e2e = await setup();
		try {
			const send = e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			await flush(8);
			e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
				fundingScript: e2e.fundingScript
			});
			await send;
			const retry = await e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			await flush(4);
			// The payer replays its own record, so the receiver never even sees a
			// second offer, let alone opens a second channel for it.
			expect(e2e.node.opens).to.have.length(1);
			expect(e2e.node.witnesses).to.have.length(1);
			expect(retry.status).to.equal('SIGNED_PENDING');
		} finally {
			e2e.stop();
		}
	});

	it('the LSP the receiver negotiates with is the one it was configured for', async () => {
		const e2e = await setup();
		try {
			const send = e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			await flush(8);
			expect(e2e.node.opens[0].peerHex).to.equal(LSP_PUBKEY);
			e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
				fundingScript: e2e.fundingScript
			});
			await send;
		} finally {
			e2e.stop();
		}
	});
});
