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
import {
	DF_PAYMENTS_STORAGE_KEY,
	DirectFundingPaymentStore
} from '../../src/lightning/direct-funding/sender/records';
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
	/** The payer's durable store, so a test can model a receipt lost on its side. */
	senderStorage: ReturnType<typeof memoryStorage>;
	payerId: string;
	/** Dials made by the payer, which must never include its own id. */
	payerDials(): number;
	/** The timeout each of the payer's dials was given. */
	payerDialTimeouts(): Array<number | undefined>;
	/** Peers a payer's lane asked to keep reconnecting to. */
	payerKeptReconnecting(): string[];
	/** Bring the receiver's connection to the payer up, as a returning phone does. */
	connectReceiver(): void;
	fundingScript: Buffer;
	/** The offer the payer will make, rebuilt from what it was given. */
	expectedOffer(): IDfOffer;
	stop(): void;
}

async function setup(
	opts: {
		paired?: boolean;
		allowSplice?: boolean;
		allowUnpairedSplice?: boolean;
		unpairedSpliceDepth?: number;
		allowZeroConf?: boolean;
		amountSat?: bigint;
		/**
		 * The payer is the receiver's introduction node (a primary paying its
		 * own lightning-first wallet), and the receiver is not connected when
		 * the send starts. The request then carries only the onion descriptor
		 * a minted request carries, naming the payer.
		 */
		payerIntroduces?: boolean;
		offerTimeoutMs?: number;
		/**
		 * The payer is not connected when the send starts, and its dial to the
		 * receiver's address takes this long to land.
		 */
		payerDialMs?: number | 'never';
	} = {}
): Promise<IEndToEnd> {
	const net = new FakeDfNetwork();
	const payerPeer: FakeDfPeer = net.add('df-e2e-payer');
	const receiverPeer: FakeDfPeer = net.add('df-e2e-receiver');
	if (opts.payerDialMs !== undefined) {
		payerPeer.dialDelayMs = opts.payerDialMs;
	} else if (!opts.payerIntroduces) {
		net.connect(payerPeer, receiverPeer);
	}

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
				transports: opts.payerIntroduces
					? [
							{
								type: DfTransportType.ONION_MESSAGE,
								host: 'primary.example',
								port: 9735,
								introNodeId: payerPeer.pubkey,
								pathKey: receiverPeer.pubkey,
								hops: [
									{
										blindedNodeId: receiverPeer.pubkey,
										encryptedData: Buffer.alloc(16, 1)
									}
								]
							}
					  ]
					: [
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
		allowUnpairedSplice: opts.allowUnpairedSplice === true,
		...(opts.unpairedSpliceDepth !== undefined
			? { unpairedSpliceDepth: opts.unpairedSpliceDepth }
			: {}),
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

	const payerRegistry = new DfTransportRegistry(undefined, {
		isPeerConnected: (hex) => payerPeer.isPeerConnected(hex),
		nodeId: () => payerPeer.pubkey,
		connectPeer: (hex, host, port, timeoutMs) =>
			payerPeer.connectPeer(hex, host, port, timeoutMs)
	});
	const payerFactory = new DfDirectPeerLaneFactory(payerPeer);
	payerRegistry.register({
		type: DfTransportType.DIRECT_PEER,
		enabled: true,
		load: () => payerFactory
	});
	const wallet = new FakeSenderWallet([coin]);
	const senderStorage = memoryStorage();
	const payments = new DirectFundingPaymentStore({ storage: senderStorage });
	const sender = new DirectFundingSender(
		{
			wallet,
			registry: payerRegistry,
			payments,
			chainHash: (): Buffer => chainHashForNetwork(Network.REGTEST)
		},
		{
			offerResendDelaysMs: [],
			offerTimeoutMs: opts.offerTimeoutMs ?? 4_000,
			receiptTimeoutMs: 500
		}
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
		senderStorage,
		payerId: payerPeer.id,
		payerDials: (): number => payerPeer.dialAttempts,
		payerDialTimeouts: (): Array<number | undefined> => payerPeer.dialTimeouts,
		payerKeptReconnecting: (): string[] => payerPeer.keptReconnecting,
		connectReceiver: (): void => net.connect(receiverPeer, payerPeer),
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

	it('a payer that signs messages rather than digests is served exactly the same', async () => {
		// LND, Core, Electrum and hardware wallets sign a message, not a raw
		// digest. The offer carries that proof in its odd TLV with a zeroed
		// digest field, the receiver verifies it, and the rest of the exchange
		// is byte for byte what a digest-signing payer gets.
		const e2e = await setup();
		e2e.wallet.signsMessages = true;
		try {
			const send = e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			await flush(8);
			expect(
				e2e.node.opens,
				'the receiver never started an open'
			).to.have.length(1);
			e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
				fundingScript: e2e.fundingScript
			});
			const result = await send;
			expect(result.attested).to.equal(true);
			expect(result.status).to.equal('SIGNED_PENDING');
			expect(result.receiptPreimageHex).to.equal(e2e.record.preimageHex);
			expect(e2e.node.witnesses).to.have.length(1);
		} finally {
			e2e.stop();
		}
	});

	it('a payer that can only sign transactions (probe proof) is served exactly the same', async () => {
		const e2e = await setup();
		e2e.wallet.signsProbes = true;
		try {
			const send = e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			await flush(8);
			expect(
				e2e.node.opens,
				'the receiver never started an open'
			).to.have.length(1);
			e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
				fundingScript: e2e.fundingScript
			});
			const result = await send;
			expect(result.attested).to.equal(true);
			expect(result.status).to.equal('SIGNED_PENDING');
			expect(result.receiptPreimageHex).to.equal(e2e.record.preimageHex);
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
			// A paired payer's splice locks as the channel type says.
			expect(e2e.node.splices[0].options).to.deep.equal({
				lockAtDepth: undefined
			});
		} finally {
			e2e.stop();
		}
	});

	// Issue #760: the same exchange for a payer the receiver never paired with.
	// The payer side is untouched; what changes is the funding the receiver
	// negotiates behind it, a splice that locks at depth rather than a second
	// channel. The payer signs whatever funding it is handed and verifies the
	// shared-input arm exactly as it does for a paired splice.
	it('splices an existing channel for an unpaired payer with a confirmed coin when allowUnpairedSplice is on, locking at depth', async () => {
		const e2e = await setup({
			allowSplice: true,
			allowUnpairedSplice: true,
			unpairedSpliceDepth: 6
		});
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
			expect(e2e.node.splices[0].options).to.deep.equal({ lockAtDepth: 6 });
			expect(e2e.node.splices[0].inputs[0].confirmed).to.equal(true);
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

	// Issue #767: a payer that lost the receipt after the witness left asks the
	// receiver, still holding its session, to replay it. No second channel, no
	// second witness, and the payer recovers its proof of delivery.
	it('recovers a receipt the payer lost, from the real receiver, with no second open', async () => {
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
			const first = await send;
			expect(first.receiptPreimageHex).to.equal(e2e.record.preimageHex);

			// The payer loses the receipt (a crash before it was recorded), while
			// the witness had provably left: drop it from the payer's store and
			// reload, leaving the receiver's own session untouched.
			const requestIdHex = Buffer.from(e2e.record.requestId, 'hex').toString(
				'hex'
			);
			const rows = JSON.parse(
				e2e.senderStorage.loadWalletData(DF_PAYMENTS_STORAGE_KEY)!
			);
			expect(rows[0].witnessSent).to.equal(true);
			delete rows[0].receiptPreimage;
			delete rows[0].broadcastTx;
			e2e.senderStorage.saveWalletData(
				DF_PAYMENTS_STORAGE_KEY,
				JSON.stringify(rows)
			);
			e2e.payments.restore();
			expect(
				e2e.payments.get(requestIdHex)!.receiptPreimage,
				'the receipt is gone from the payer'
			).to.equal(undefined);

			const recovered = await e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING,
				recoverReceipt: true
			});
			await flush(4);
			// The receiver replayed its recorded receipt; it never opened a second
			// channel, and no new witness was signed.
			expect(e2e.node.opens, 'no second open').to.have.length(1);
			expect(recovered.status).to.equal('SIGNED_PENDING');
			expect(recovered.receiptPreimageHex, 'the receipt came back').to.equal(
				e2e.record.preimageHex
			);
			expect(
				e2e.payments.get(requestIdHex)!.receiptPreimage,
				'and was persisted again'
			).to.equal(e2e.record.preimageHex);
			expect(recovered.caveat).to.equal(undefined);
		} finally {
			e2e.stop();
		}
	});

	// Issue #806: a primary paying its own lightning-first wallet, which is in
	// the background (disconnected) when the send starts and comes back a
	// moment later. The payer used to dial its own node id for the whole offer
	// window and answer EXCHANGE_TIMEOUT.
	it('the introduction node pays a receiver that connects after the send starts', async () => {
		const e2e = await setup({ payerIntroduces: true });
		try {
			const send = e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			await flush(8);
			expect(
				e2e.node.opens,
				'nothing can reach an absent receiver'
			).to.have.length(0);
			e2e.connectReceiver();
			await flush(8);
			expect(e2e.node.opens, 'the held offer never arrived').to.have.length(1);
			e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
				fundingScript: e2e.fundingScript
			});
			const result = await send;
			expect(result.status).to.equal('SIGNED_PENDING');
			expect(result.attested).to.equal(true);
			expect(e2e.payerDials(), 'the payer dialed').to.equal(0);
		} finally {
			e2e.stop();
		}
	});

	it('the introduction node refuses pre-witness when the receiver never connects', async () => {
		const e2e = await setup({ payerIntroduces: true, offerTimeoutMs: 60 });
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
			expect((error as { code?: string })?.code).to.equal('UNREACHABLE');
			expect((error as Error).message).to.contain(
				'the receiver did not connect before the offer window closed'
			);
			expect(e2e.payerDials(), 'the payer dialed').to.equal(0);
			expect(e2e.node.opens).to.have.length(0);
			expect(e2e.wallet.frozen.size).to.equal(0);
			expect(e2e.payments.list()[0].status).to.equal('ABORTED');
		} finally {
			e2e.stop();
		}
	});

	// Issue #853: dial time used to sit in front of the offer window, and the
	// node bounded each dial at its own 30 s handshake default. Scaled down here:
	// the window stands in for 120 s and the dials for 45 s and forever.
	describe('a stranger payer that has to dial', () => {
		async function sendTimed(
			e2e: IEndToEnd,
			whileRunning: () => Promise<void> = async () => undefined
		): Promise<{ elapsed: number; error: unknown; status?: string }> {
			const started = Date.now();
			const send = e2e.sender.send(e2e.request, {
				amountSat: AMOUNT,
				maxTotalFeeSat: FEE_CEILING
			});
			send.catch(() => undefined);
			await whileRunning();
			try {
				const result = await send;
				return {
					elapsed: Date.now() - started,
					error: null,
					status: result.status
				};
			} catch (err) {
				return { elapsed: Date.now() - started, error: err };
			}
		}

		async function waitFor(condition: () => boolean): Promise<void> {
			for (let i = 0; i < 200 && !condition(); i++) {
				await new Promise((resolve) => setTimeout(resolve, 10));
			}
			expect(condition(), 'the condition never held').to.equal(true);
		}

		it('pays over a slow dial, handing the dial the whole offer window', async () => {
			const e2e = await setup({ payerDialMs: 300, offerTimeoutMs: 1_500 });
			try {
				const { elapsed, error, status } = await sendTimed(e2e, async () => {
					await waitFor(() => e2e.node.opens.length === 1);
					e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
						fundingScript: e2e.fundingScript
					});
				});
				expect(error).to.equal(null);
				expect(status).to.equal('SIGNED_PENDING');
				expect(elapsed).to.be.below(1_500);
				expect(e2e.payerDials()).to.equal(1);
				expect(e2e.payerDialTimeouts()[0]).to.be.within(1_300, 1_500);
			} finally {
				e2e.stop();
			}
		});

		it('spends the dial from the offer window rather than adding it on', async () => {
			const e2e = await setup({ payerDialMs: 400, offerTimeoutMs: 600 });
			try {
				const { elapsed, error } = await sendTimed(e2e);
				expect((error as { code?: string })?.code).to.equal('EXCHANGE_TIMEOUT');
				expect(e2e.node.opens, 'the offer never arrived').to.have.length(1);
				expect(elapsed).to.be.within(550, 900);
				expect(e2e.wallet.frozen.size).to.equal(0);
			} finally {
				e2e.stop();
			}
		});

		// Issue #854: the payer reads the request before anyone presses Send.
		it('prepare starts one dial, returns before it lands, and records nothing', async () => {
			const e2e = await setup({ payerDialMs: 300 });
			try {
				const prepared = e2e.sender.prepare(e2e.request);
				expect(prepared).to.deep.include({
					requestId: e2e.record.requestId,
					receiverNodeId: e2e.node.nodeId.toString('hex'),
					amountSat: null,
					expiresAt: e2e.record.expiresAt,
					connection: 'connecting',
					peerNodeId: e2e.node.nodeId.toString('hex')
				});
				expect(e2e.payerDials()).to.equal(1);
				expect(e2e.payerDialTimeouts()).to.deep.equal([4_000]);
				expect(e2e.payments.list()).to.deep.equal([]);
				expect(e2e.wallet.frozen.size).to.equal(0);
				expect(e2e.wallet.listSpendable()).to.have.length(1);
				await flush(8);
				expect(e2e.node.opens).to.have.length(0);
			} finally {
				e2e.stop();
			}
		});

		it('a send made while the prepared dial runs joins it and offers when it lands', async () => {
			const e2e = await setup({ payerDialMs: 400, offerTimeoutMs: 1_500 });
			try {
				e2e.sender.prepare(e2e.request);
				await new Promise((resolve) => setTimeout(resolve, 250));
				let offeredAfterMs = 0;
				const { error, status } = await sendTimed(e2e, async () => {
					const sendStarted = Date.now();
					await waitFor(() => e2e.node.opens.length === 1);
					offeredAfterMs = Date.now() - sendStarted;
					e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
						fundingScript: e2e.fundingScript
					});
				});
				expect(error).to.equal(null);
				expect(status).to.equal('SIGNED_PENDING');
				expect(e2e.payerDials(), 'one socket').to.equal(1);
				// What was left of the prepared dial, not a dial of its own.
				expect(offeredAfterMs).to.be.below(350);
			} finally {
				e2e.stop();
			}
		});

		// A prepared dial arms no reconnect, and this send dials nothing to lift that.
		it('a send over the connection prepare opened keeps reconnecting to it', async () => {
			const e2e = await setup({ payerDialMs: 20 });
			try {
				e2e.sender.prepare(e2e.request);
				await new Promise((resolve) => setTimeout(resolve, 80));
				const { error } = await sendTimed(e2e, async () => {
					await waitFor(() => e2e.node.opens.length === 1);
					e2e.node.completeNegotiation(e2e.coin, e2e.expectedOffer(), {
						fundingScript: e2e.fundingScript
					});
				});
				expect(error).to.equal(null);
				expect(e2e.payerDials()).to.equal(1);
				expect(e2e.payerKeptReconnecting()).to.include(
					e2e.node.nodeId.toString('hex')
				);
			} finally {
				e2e.stop();
			}
		});

		it('refuses UNREACHABLE when the window closes on a dial that never lands', async () => {
			const e2e = await setup({ payerDialMs: 'never', offerTimeoutMs: 200 });
			try {
				const { elapsed, error } = await sendTimed(e2e);
				expect((error as { code?: string })?.code).to.equal('UNREACHABLE');
				expect(elapsed).to.be.within(180, 500);
				expect(e2e.payerDials()).to.equal(1);
				expect(e2e.node.opens).to.have.length(0);
				expect(e2e.wallet.frozen.size).to.equal(0);
				expect(e2e.payments.list()[0].status).to.equal('ABORTED');
			} finally {
				e2e.stop();
			}
		});
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
