/**
 * The direct-funding payer engine (issue #613, LFBW port #532 workstream 4D).
 *
 * Two things are being pinned here. The seven checks rev 2 makes a payer's MUST,
 * each of them failing closed before any signature exists; and the never-reject
 * contract, which says the call can only resolve once the witness has left the
 * device, whatever happens afterwards.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import {
	decodeDfOffer,
	encodeDfOfferAck,
	encodeDfReceipt,
	IDfOffer
} from '../../src/lightning/direct-funding/messages';
import {
	DirectFundingError,
	DirectFundingErrorCode,
	DfTransportType
} from '../../src/lightning/direct-funding/types';
import { DirectFundingSender } from '../../src/lightning/direct-funding/sender/engine';
import {
	DirectFundingPaymentStore,
	DF_PAYMENTS_STORAGE_KEY
} from '../../src/lightning/direct-funding/sender/records';
import { chainHashForNetwork } from '../../src/lightning/direct-funding/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	acceptingReceiver,
	FakeSenderWallet,
	ISignRequestOptions,
	ITestRequest,
	makeCoin,
	memoryStorage,
	mintRequest,
	registryWith,
	ScriptedReceiverLane,
	unreachableRegistry
} from './helpers/df-sender';

const REGTEST_HASH = chainHashForNetwork(Network.REGTEST);

interface IHarness {
	sender: DirectFundingSender;
	wallet: FakeSenderWallet;
	payments: DirectFundingPaymentStore;
	lane: ScriptedReceiverLane;
	storage: ReturnType<typeof memoryStorage>;
	request: ITestRequest;
}

/** One payer, one coin, one lane, one scripted receiver. */
function harness(
	opts: {
		request?: ITestRequest;
		coinValueSat?: number;
		kind?: 'p2wpkh' | 'p2tr';
		receiver?: Parameters<typeof acceptingReceiver>[1];
		storage?: ReturnType<typeof memoryStorage>;
		chainHash?: Buffer;
		unreachable?: boolean;
	} = {}
): IHarness {
	const request = opts.request ?? mintRequest();
	const coin = makeCoin(opts.coinValueSat ?? 200_000, opts.kind ?? 'p2wpkh');
	const wallet = new FakeSenderWallet([coin]);
	const storage = opts.storage ?? memoryStorage();
	const payments = new DirectFundingPaymentStore({ storage });
	payments.restore();
	const lane = new ScriptedReceiverLane(
		request,
		acceptingReceiver(request, opts.receiver ?? {})
	);
	const sender = new DirectFundingSender(
		{
			wallet,
			registry: opts.unreachable ? unreachableRegistry() : registryWith(lane),
			payments,
			chainHash: (): Buffer => opts.chainHash ?? REGTEST_HASH
		},
		{ offerResendDelaysMs: [], offerTimeoutMs: 5_000, receiptTimeoutMs: 200 }
	);
	return { sender, wallet, payments, lane, storage, request };
}

/** Run a send that is expected to be refused, and hand back the refusal. */
async function refusal(promise: Promise<unknown>): Promise<DirectFundingError> {
	try {
		await promise;
	} catch (err) {
		expect(err, 'expected a DirectFundingError').to.be.instanceOf(
			DirectFundingError
		);
		return err as DirectFundingError;
	}
	return expect.fail('expected the send to be refused');
}

/** A harness whose receiver builds its sign request from `opts`. */
function withSignRequest(opts: ISignRequestOptions): IHarness {
	return harness({ receiver: opts });
}

describe('Direct funding sender: the happy path', () => {
	it('offers a coin, verifies, signs, and comes back with the receipt', async () => {
		let seenWitness: Buffer[] | null = null;
		const h = harness({
			receiver: {
				includeRawTx: true,
				onWitness: (w): void => {
					seenWitness = w;
				}
			}
		});
		const result = await h.sender.send(h.request.encoded, {
			amountSat: 100_000n
		});
		expect(result.attested).to.equal(true);
		expect(result.status).to.equal('SIGNED_PENDING');
		expect(result.receiptPreimageHex).to.equal(
			h.request.preimage.toString('hex')
		);
		expect(result.amountSat).to.equal(100_000);
		expect(result.broadcastTxHex).to.be.a('string');
		expect(result.caveat).to.equal(undefined);
		// P2WPKH: a DER signature and the pubkey.
		expect(seenWitness).to.have.length(2);
	});

	it('freezes the offered coin, and does so before the witness leaves', async () => {
		let frozenAtWitness = false;
		const h = harness({});
		const coin = h.wallet.coins[0];
		const receiver = acceptingReceiver(h.request, {
			onWitness: (): void => {
				frozenAtWitness = h.wallet.frozen.has(`${coin.txidHex}:${coin.vout}`);
			}
		});
		const lane = new ScriptedReceiverLane(h.request, receiver);
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		await sender.send(h.request.encoded, { amountSat: 100_000n });
		expect(
			frozenAtWitness,
			'the coin was still selectable at witness time'
		).to.equal(true);
		expect(h.wallet.listSpendable()).to.deep.equal([]);
	});

	it('persists the attestation, transaction and witness before emitting', async () => {
		let recordAtWitness: unknown = null;
		const h = harness({});
		const receiver = acceptingReceiver(h.request, {
			onWitness: (): void => {
				recordAtWitness = h.payments.get(h.request.requestId.toString('hex'));
			}
		});
		const lane = new ScriptedReceiverLane(h.request, receiver);
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		await sender.send(h.request.encoded, { amountSat: 100_000n });
		const record = recordAtWitness as {
			status: string;
			attestation?: unknown;
			negotiatedTx?: string;
			witness?: string[];
			fundingTxid?: string;
		} | null;
		expect(record, 'no record existed when the witness went out').to.not.equal(
			null
		);
		expect(record!.status).to.equal('SIGNED_PENDING');
		expect(record!.attestation).to.not.equal(undefined);
		expect(record!.negotiatedTx).to.be.a('string');
		expect(record!.witness).to.have.length(2);
		expect(record!.fundingTxid).to.be.a('string');
		// And it is on disk, not just in memory: a restart must find it.
		const persisted = JSON.parse(
			h.storage.loadWalletData(DF_PAYMENTS_STORAGE_KEY)!
		);
		expect(persisted[0].status).to.equal('SIGNED_PENDING');
	});

	it('signs a taproot coin over the full prevout set', async () => {
		const h = harness({ kind: 'p2tr' });
		let witness: Buffer[] | null = null;
		const lane = new ScriptedReceiverLane(
			h.request,
			acceptingReceiver(h.request, {
				onWitness: (w): void => {
					witness = w;
				}
			})
		);
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		const result = await sender.send(h.request.encoded, {
			amountSat: 100_000n
		});
		expect(result.attested).to.equal(true);
		expect(witness).to.have.length(1);
		expect((witness as unknown as Buffer[])[0]).to.have.length(64);
	});
});

describe('Direct funding sender: the envelope and the amount', () => {
	it('refuses a request for another chain', async () => {
		const h = harness({ chainHash: Buffer.alloc(32, 9) });
		const err = await refusal(
			h.sender.send(h.request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.WRONG_CHAIN);
	});

	it('refuses an expired request', async () => {
		const request = mintRequest({ ttlMs: 1_000 });
		const h = harness({ request });
		const err = await refusal(
			h.sender.send(request.encoded, {
				amountSat: 100_000n,
				now: Date.now() + 5_000
			})
		);
		expect(err.code).to.equal(DirectFundingErrorCode.EXPIRED);
	});

	it('refuses an envelope signed by someone other than the node it names', async () => {
		const request = mintRequest();
		// Re-sign the same bytes with a different key: the signature verifies and
		// recovers SOME key, just not the one the envelope names.
		const other = mintRequest({ nodePrivkey: crypto.randomBytes(32) });
		const bytes = Buffer.from(request.encoded, 'base64url');
		const forgedBytes = Buffer.from(other.encoded, 'base64url');
		forgedBytes.set(request.nodeId, 1 + 16 + 32);
		const h = harness({ request });
		const err = await refusal(
			h.sender.send(forgedBytes.toString('base64url'), { amountSat: 100_000n })
		);
		expect([
			DirectFundingErrorCode.WRONG_SIGNER,
			DirectFundingErrorCode.INVALID_SIGNATURE
		]).to.include(err.code);
		expect(bytes.length).to.be.greaterThan(0);
	});

	it('refuses garbage that is not a request at all', async () => {
		const h = harness({});
		const err = await refusal(h.sender.send('not-a-request', {}));
		expect(err.code).to.equal(DirectFundingErrorCode.MALFORMED);
	});

	it('needs an amount when the request fixes none', async () => {
		const h = harness({});
		const err = await refusal(h.sender.send(h.request.encoded, {}));
		expect(err.code).to.equal(DirectFundingErrorCode.AMOUNT_REQUIRED);
	});

	it('refuses an amount that contradicts the one the request fixed', async () => {
		const request = mintRequest({ amountSat: 50_000n });
		const h = harness({ request });
		const err = await refusal(
			h.sender.send(request.encoded, { amountSat: 60_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.AMOUNT_MISMATCH);
	});

	it('takes the fixed amount when the caller names none', async () => {
		const request = mintRequest({ amountSat: 50_000n });
		const h = harness({ request });
		const result = await h.sender.send(request.encoded, {});
		expect(result.amountSat).to.equal(50_000);
	});
});

describe('Direct funding sender: coin selection', () => {
	it('refuses with its own code when no single coin covers the payment', async () => {
		const h = harness({ coinValueSat: 10_000 });
		const err = await refusal(
			h.sender.send(h.request.encoded, { amountSat: 100_000n })
		);
		// Its own code, because a payer that cannot fund is not a payer that
		// could not connect, and the caller reacts to those differently.
		expect(err.code).to.equal(DirectFundingErrorCode.NO_SUITABLE_UTXO);
		expect(err.code).to.not.equal(DirectFundingErrorCode.UNREACHABLE);
	});

	it('reports an unreachable receiver as a transport failure, not a funding one', async () => {
		const h = harness({ unreachable: true });
		const err = await refusal(
			h.sender.send(h.request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.UNREACHABLE);
	});

	it('takes the largest coin that covers the amount plus the fee ceiling', async () => {
		const small = makeCoin(120_000);
		const large = makeCoin(300_000);
		const wallet = new FakeSenderWallet([small, large]);
		const request = mintRequest();
		const lane = new ScriptedReceiverLane(request, acceptingReceiver(request));
		const storage = memoryStorage();
		const payments = new DirectFundingPaymentStore({ storage });
		const sender = new DirectFundingSender(
			{
				wallet,
				registry: registryWith(lane),
				payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		const result = await sender.send(request.encoded, { amountSat: 100_000n });
		expect(result.spentTxid).to.equal(large.txidHex);
	});
});

describe('Direct funding sender: the seven sign-request checks', () => {
	/** Run a send whose receiver builds a bad sign request, expecting a refusal. */
	async function refusedBy(opts: ISignRequestOptions): Promise<string> {
		const h = withSignRequest(opts);
		const err = await refusal(
			h.sender.send(h.request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.SIGN_REQUEST_REFUSED);
		// Nothing was signed, so nothing was reserved either.
		expect(
			h.wallet.frozen.size,
			'a refused sign request froze a coin'
		).to.equal(0);
		return err.message;
	}

	// ── 1. Input ──

	it('refuses a transaction that does not spend our coin at the sequence we offered', async () => {
		const message = await refusedBy({ sequence: 0xffffffff });
		expect(message).to.contain('sequence');
	});

	it('refuses a transaction spending a second coin of ours', async () => {
		const second = makeCoin(80_000);
		const first = makeCoin(200_000);
		const wallet = new FakeSenderWallet([first, second]);
		const request = mintRequest();
		const storage = memoryStorage();
		const payments = new DirectFundingPaymentStore({ storage });
		const lane = new ScriptedReceiverLane(
			request,
			acceptingReceiver(request, {
				extraInputs: [
					{
						txid: Buffer.from(second.txidHex, 'hex'),
						vout: second.vout,
						prevout: { valueSat: second.valueSat, script: second.script }
					}
				]
			})
		);
		const sender = new DirectFundingSender(
			{
				wallet,
				registry: registryWith(lane),
				payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		const err = await refusal(
			sender.send(request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.SIGN_REQUEST_REFUSED);
		expect(err.message).to.contain('second coin of ours');
	});

	// ── 2. Shape ──

	it('refuses a version other than 2', async () => {
		expect(await refusedBy({ version: 1 })).to.contain('version');
	});

	it('refuses a time-based locktime', async () => {
		expect(await refusedBy({ locktime: 500_000_000 })).to.contain('locktime');
	});

	it('refuses more than eight outputs', async () => {
		expect(await refusedBy({ extraOutputs: 8 })).to.contain('outputs');
	});

	it('refuses a prevout list that does not cover every input', async () => {
		const extra = makeCoin(50_000);
		expect(
			await refusedBy({
				dropPrevouts: true,
				extraInputs: [
					{
						txid: Buffer.from(extra.txidHex, 'hex'),
						vout: 0,
						prevout: { valueSat: extra.valueSat, script: extra.script }
					}
				]
			})
		).to.contain('prevouts');
	});

	// ── 3. Change and fee ──

	it('refuses a transaction that costs us more than the fee ceiling', async () => {
		const h = harness({ receiver: { feeSat: 50_000n } });
		const err = await refusal(
			h.sender.send(h.request.encoded, {
				amountSat: 100_000n,
				maxTotalFeeSat: 1_000n
			})
		);
		expect(err.message).to.contain('above the 1000 sat allowed');
	});

	it('accepts a missing change output when the ceiling still covers it', async () => {
		// The dust arm: honest change below the dust limit becomes fee, and the
		// ceiling is what bounds what that costs us.
		const h = harness({ coinValueSat: 100_300, receiver: { noChange: true } });
		const result = await h.sender.send(h.request.encoded, {
			amountSat: 100_000n,
			maxTotalFeeSat: 300n
		});
		expect(result.attested).to.equal(true);
		expect(result.status).to.equal('SIGNED_PENDING');
	});

	it('refuses a missing change output the ceiling does NOT cover', async () => {
		const h = harness({ coinValueSat: 200_000, receiver: { noChange: true } });
		const err = await refusal(
			h.sender.send(h.request.encoded, {
				amountSat: 100_000n,
				maxTotalFeeSat: 1_000n
			})
		);
		expect(err.message).to.contain('above the 1000 sat allowed');
	});

	it('refuses change paid to a script that is not ours', async () => {
		const message = await refusedBy({
			changeScript: bitcoin.payments.p2wpkh({
				hash: crypto.randomBytes(20)
			}).output!
		});
		// Our change never comes back, so the whole coin reads as our cost.
		expect(message).to.contain('fees');
	});

	// ── 4. Funding output ──

	it('refuses a funding output that is not the attested 2-of-2', async () => {
		expect(await refusedBy({ fundingOutputIndex: 1 })).to.contain(
			'does not match the attested 2-of-2'
		);
	});

	it('refuses a funding output holding less than the amount we are paying', async () => {
		expect(await refusedBy({ fundingValueSat: 90_000n })).to.contain(
			'less than the 100000 sat we are paying'
		);
	});

	// ── The splice arm ──

	it('accepts a splice whose new funding carries the old capacity plus ours', async () => {
		const h = harness({
			receiver: { sharedInput: { valueSat: 500_000n } }
		});
		const result = await h.sender.send(h.request.encoded, {
			amountSat: 100_000n
		});
		expect(result.attested).to.equal(true);
	});

	it('refuses a splice whose shared input is not the attested channel funding', async () => {
		expect(
			await refusedBy({
				sharedInput: {
					valueSat: 500_000n,
					script: bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) })
						.output!
				}
			})
		).to.contain('shared input is not the attested channel funding');
	});

	it('refuses a splice whose new funding drops the old capacity', async () => {
		expect(
			await refusedBy({
				sharedInput: { valueSat: 500_000n },
				fundingValueSat: 100_000n
			})
		).to.contain('below the');
	});

	// ── 5. Attestation ──

	it('refuses an attestation that does not verify at all', async () => {
		expect(await refusedBy({ forgeAttestation: true })).to.match(
			/attestation (signature is invalid|was signed by a different node)/
		);
	});

	it('refuses an attestation signed by a different node than the request named', async () => {
		expect(await refusedBy({ attestWith: crypto.randomBytes(32) })).to.contain(
			'signed by a different node'
		);
	});

	// ── 6. Prevouts ──

	it('refuses prevouts that do not match our own input', async () => {
		expect(
			await refusedBy({
				manglePrevout: (prevouts): void => {
					prevouts[0] = { ...prevouts[0], valueSat: prevouts[0].valueSat + 1n };
				}
			})
		).to.contain('do not match our own input');
	});

	it('checks every other prevout against the chain when signing taproot', async () => {
		const coin = makeCoin(200_000, 'p2tr');
		const foreign = makeCoin(70_000);
		const wallet = new FakeSenderWallet([coin]);
		// The foreign coin is NOT ours, but its prevout is signing input under
		// BIP 341, so the payer resolves it from our own chain source.
		wallet.chain.set(foreign.txidHex, foreign.prevTx.toBuffer());
		const request = mintRequest();
		const payments = new DirectFundingPaymentStore({
			storage: memoryStorage()
		});
		const lane = new ScriptedReceiverLane(
			request,
			acceptingReceiver(request, {
				extraInputs: [
					{
						txid: Buffer.from(foreign.txidHex, 'hex'),
						vout: 0,
						// A lie: the chain says 70000.
						prevout: { valueSat: 999_999n, script: foreign.script }
					}
				]
			})
		);
		const sender = new DirectFundingSender(
			{
				wallet,
				registry: registryWith(lane),
				payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		const err = await refusal(
			sender.send(request.encoded, { amountSat: 100_000n })
		);
		expect(err.message).to.contain('does not match chain truth');
	});

	it('does not fetch foreign prevouts for a P2WPKH input', async () => {
		// BIP 143 commits to our own value and script only, so an unresolvable
		// foreign prevout must not cost an honest payer its payment.
		const foreign = makeCoin(70_000);
		const h = harness({
			receiver: {
				extraInputs: [
					{
						txid: Buffer.from(foreign.txidHex, 'hex'),
						vout: 0,
						prevout: { valueSat: 999_999n, script: foreign.script }
					}
				]
			}
		});
		h.wallet.chainFails = true;
		const result = await h.sender.send(h.request.encoded, {
			amountSat: 100_000n
		});
		expect(result.attested).to.equal(true);
	});

	// ── 7. Amount ──

	it('refuses a funding output that does not honor a fixed-amount request', async () => {
		const request = mintRequest({ amountSat: 100_000n });
		const h = harness({
			request,
			receiver: { fundingValueSat: 40_000n }
		});
		const err = await refusal(h.sender.send(request.encoded, {}));
		expect(err.message).to.contain('less than the 100000 sat we are paying');
	});

	it('ignores a sign request naming a different offer', async () => {
		const request = mintRequest();
		const coin = makeCoin(200_000);
		const wallet = new FakeSenderWallet([coin]);
		const payments = new DirectFundingPaymentStore({
			storage: memoryStorage()
		});
		const lane = new ScriptedReceiverLane(
			request,
			acceptingReceiver(request, { offerId: Buffer.alloc(16, 7) })
		);
		const sender = new DirectFundingSender(
			{
				wallet,
				registry: registryWith(lane),
				payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], offerTimeoutMs: 80, receiptTimeoutMs: 80 }
		);
		const err = await refusal(
			sender.send(request.encoded, { amountSat: 100_000n })
		);
		// It is not refused as a bad transaction: it is not our exchange at all,
		// so the send runs out of time instead.
		expect(err.code).to.equal(DirectFundingErrorCode.EXCHANGE_TIMEOUT);
	});
});

describe('Direct funding sender: the never-reject contract', () => {
	/** Everything below this line has a witness on the wire. */
	async function committed(
		receiver: Parameters<typeof acceptingReceiver>[1]
	): Promise<Awaited<ReturnType<DirectFundingSender['send']>>> {
		const h = harness({ receiver });
		return h.sender.send(h.request.encoded, { amountSat: 100_000n });
	}

	it('resolves when the receipt never arrives', async () => {
		const result = await committed({ noReceipt: true });
		expect(result.status).to.equal('SIGNED_PENDING');
		expect(result.receiptPreimageHex).to.equal(null);
		expect(result.attested).to.equal(true);
		expect(result.caveat).to.contain('receipt');
	});

	it('resolves, and says nothing happened, when the receipt is forged', async () => {
		const result = await committed({ forgeReceipt: true });
		expect(result.receiptPreimageHex).to.equal(null);
		expect(result.status).to.equal('SIGNED_PENDING');
		expect(result.caveat).to.contain('receipt');
	});

	it('resolves when a post-witness frame is malformed', async () => {
		const request = mintRequest();
		const h = harness({ request, receiver: { noReceipt: true } });
		const lane = new ScriptedReceiverLane(request, (l, subtype, body): void => {
			acceptingReceiver(request, { noReceipt: true })(l, subtype, body);
			if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_WITNESS) {
				// Junk sealed under the right key: it opens, and then fails to
				// decode as a receipt. A throw here used to be a rejection.
				l.reply(
					BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
					Buffer.from('not a tlv stream at all', 'utf8')
				);
			}
		});
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 200 }
		);
		const result = await sender.send(request.encoded, { amountSat: 100_000n });
		expect(result.status).to.equal('SIGNED_PENDING');
		expect(result.caveat).to.be.a('string');
	});

	it('ignores a decline that arrives after the witness', async () => {
		const request = mintRequest();
		const h = harness({ request });
		let offer: IDfOffer | null = null;
		const inner = acceptingReceiver(request, { noReceipt: true });
		const lane = new ScriptedReceiverLane(request, (l, subtype, body): void => {
			if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
				offer = decodeDfOffer(body);
			}
			inner(l, subtype, body);
			if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_WITNESS && offer) {
				l.reply(
					BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK,
					encodeDfOfferAck({
						offerId: offer.offerId,
						accepted: false,
						reason: 'changed my mind'
					})
				);
			}
		});
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 200 }
		);
		const result = await sender.send(request.encoded, { amountSat: 100_000n });
		expect(result.status).to.equal('SIGNED_PENDING');
	});

	it('still rejects a decline that arrives BEFORE the witness', async () => {
		const h = harness({ receiver: { decline: 'no liquidity peer' } });
		const err = await refusal(
			h.sender.send(h.request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.OFFER_DECLINED);
		expect(err.message).to.contain('no liquidity peer');
		expect(h.wallet.frozen.size).to.equal(0);
	});

	it('withholds the witness, and refuses, when the record cannot be persisted', async () => {
		const storage = memoryStorage();
		const h = harness({ storage });
		let sawWitness = false;
		const lane = new ScriptedReceiverLane(
			h.request,
			acceptingReceiver(h.request, {
				onWitness: (): void => {
					sawWitness = true;
				}
			})
		);
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		// Fail the write that would RECORD the witness, not the one that opened
		// the record: the refusal has to happen at the last moment it is free.
		storage.failWhen = (value): boolean => value.includes('SIGNED_PENDING');
		const err = await refusal(
			sender.send(h.request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.NOT_PERSISTED);
		expect(
			sawWitness,
			'the witness left against an unpersisted record'
		).to.equal(false);
		// And the coin is released again, since nothing was spent.
		expect(h.wallet.frozen.size).to.equal(0);
	});

	it('refuses before signing when the coin cannot be reserved', async () => {
		const h = harness({});
		h.wallet.freezeFails = true;
		let sawWitness = false;
		const lane = new ScriptedReceiverLane(
			h.request,
			acceptingReceiver(h.request, {
				onWitness: (): void => {
					sawWitness = true;
				}
			})
		);
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		const err = await refusal(
			sender.send(h.request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.SIGN_REQUEST_REFUSED);
		expect(sawWitness).to.equal(false);
	});
});

describe('Direct funding sender: idempotency (defect D6)', () => {
	it('two concurrent sends share one attempt, one offer and one spend', async () => {
		const offers: string[] = [];
		const request = mintRequest();
		const h = harness({ request, receiver: { noReceipt: true } });
		const inner = acceptingReceiver(request, {});
		const lane = new ScriptedReceiverLane(request, (l, subtype, body): void => {
			if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
				offers.push(decodeDfOffer(body).offerId.toString('hex'));
			}
			inner(l, subtype, body);
		});
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		const [a, b] = await Promise.all([
			sender.send(request.encoded, { amountSat: 100_000n }),
			sender.send(request.encoded, { amountSat: 100_000n })
		]);
		expect(offers, 'a second offer went out').to.have.length(1);
		expect(a.offerId).to.equal(b.offerId);
		expect(a.spentTxid).to.equal(b.spentTxid);
		expect(h.payments.list()).to.have.length(1);
	});

	it('a sequential retry replays the recorded attempt, without a second coin', async () => {
		const second = makeCoin(400_000);
		const request = mintRequest();
		const h = harness({ request });
		const offers: string[] = [];
		const inner = acceptingReceiver(request, {});
		const lane = new ScriptedReceiverLane(request, (l, subtype, body): void => {
			if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
				offers.push(decodeDfOffer(body).offerId.toString('hex'));
			}
			inner(l, subtype, body);
		});
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 100 }
		);
		const first = await sender.send(request.encoded, { amountSat: 100_000n });
		// A second, larger coin the retry would pick if it re-ran selection: the
		// first attempt froze the original, so the fork's retry chose this one and
		// genuinely paid twice.
		h.wallet.coins.push(second);
		const retry = await sender.send(request.encoded, { amountSat: 100_000n });
		expect(offers).to.have.length(1);
		expect(retry.offerId).to.equal(first.offerId);
		expect(retry.spentTxid).to.equal(first.spentTxid);
		expect(retry.spentTxid).to.not.equal(second.txidHex);
	});

	it('a retry after a crash resumes the SAME offer bytes', async () => {
		const storage = memoryStorage();
		const request = mintRequest();
		const coin = makeCoin(200_000);
		const wallet = new FakeSenderWallet([coin]);
		const bodies: string[] = [];
		const makeSender = (): DirectFundingSender => {
			const payments = new DirectFundingPaymentStore({ storage });
			payments.restore();
			const lane = new ScriptedReceiverLane(
				request,
				(l, subtype, body): void => {
					if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
						bodies.push(body.toString('hex'));
						// Answer nothing: the exchange dies where a crash would.
						return;
					}
					acceptingReceiver(request, {})(l, subtype, body);
				}
			);
			return new DirectFundingSender(
				{
					wallet,
					registry: registryWith(lane),
					payments,
					chainHash: (): Buffer => REGTEST_HASH
				},
				{ offerResendDelaysMs: [], offerTimeoutMs: 60, receiptTimeoutMs: 60 }
			);
		};
		await refusal(makeSender().send(request.encoded, { amountSat: 100_000n }));
		// The first attempt died pre-witness and closed the record, so a retry
		// replays that refusal rather than committing a second coin.
		const err = await refusal(
			makeSender().send(request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.OFFER_DECLINED);
		expect(bodies, 'the retry re-ran the exchange').to.have.length(1);
	});

	it('an idempotent replay of the sign request signs once', async () => {
		const witnesses: Buffer[][] = [];
		const h = harness({
			receiver: {
				duplicateSignRequest: true,
				onWitness: (w): void => {
					witnesses.push(w);
				}
			}
		});
		await h.sender.send(h.request.encoded, { amountSat: 100_000n });
		expect(witnesses).to.have.length(1);
	});

	it('refuses a retry that changes the amount', async () => {
		const h = harness({ receiver: { noReceipt: true } });
		await h.sender.send(h.request.encoded, { amountSat: 100_000n });
		const err = await refusal(
			h.sender.send(h.request.encoded, { amountSat: 120_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.AMOUNT_MISMATCH);
	});
});

describe('Direct funding sender: reconciling a committed payment', () => {
	async function committedHarness(): Promise<IHarness> {
		const h = harness({ receiver: { noReceipt: true } });
		await h.sender.send(h.request.encoded, { amountSat: 100_000n });
		return h;
	}

	it('moves to MEMPOOL_SEEN when the funding is known, and holds the freeze', async () => {
		const h = await committedHarness();
		const record = h.payments.pending()[0];
		h.wallet.known.set(record.fundingTxid!, false);
		await h.sender.reconcile();
		expect(h.payments.get(record.requestId)!.status).to.equal('MEMPOOL_SEEN');
		expect(h.wallet.frozen.size, 'the coin was released too early').to.equal(1);
	});

	it('moves to CONFIRMED and releases the coin once the funding confirms', async () => {
		const h = await committedHarness();
		const record = h.payments.pending()[0];
		h.wallet.known.set(record.fundingTxid!, true);
		await h.sender.reconcile();
		expect(h.payments.get(record.requestId)!.status).to.equal('CONFIRMED');
		expect(h.wallet.frozen.size).to.equal(0);
	});

	it('is FAILED only once a conflicting spend has CONFIRMED', async () => {
		const h = await committedHarness();
		const record = h.payments.pending()[0];
		// Absent from the mempool proves nothing on its own.
		await h.sender.reconcile();
		expect(h.payments.get(record.requestId)!.status).to.equal('SIGNED_PENDING');
		h.wallet.conflicts.set(
			`${record.spentTxid}:${record.spentVout}`,
			'ab'.repeat(32)
		);
		await h.sender.reconcile();
		expect(h.payments.get(record.requestId)!.status).to.equal('FAILED');
	});

	it('replays a settled payment rather than re-running it', async () => {
		const h = await committedHarness();
		const record = h.payments.pending()[0];
		h.wallet.known.set(record.fundingTxid!, true);
		await h.sender.reconcile();
		const replay = await h.sender.send(h.request.encoded, {
			amountSat: 100_000n
		});
		expect(replay.status).to.equal('CONFIRMED');
		expect(replay.offerId).to.equal(record.offerId);
	});
});

describe('Direct funding sender: the payment record', () => {
	it('survives a restart with the witness and the transaction intact', async () => {
		const storage = memoryStorage();
		const h = harness({ storage, receiver: { noReceipt: true } });
		await h.sender.send(h.request.encoded, { amountSat: 100_000n });
		const reloaded = new DirectFundingPaymentStore({ storage });
		expect(reloaded.restore()).to.equal(1);
		const record = reloaded.list()[0];
		expect(record.status).to.equal('SIGNED_PENDING');
		expect(record.witness).to.have.length(2);
		expect(bitcoin.Transaction.fromHex(record.negotiatedTx!).version).to.equal(
			2
		);
		expect(record.frozen).to.equal(true);
	});

	it('drops a row whose outpoint did not come back intact', () => {
		const storage = memoryStorage();
		storage.saveWalletData(
			DF_PAYMENTS_STORAGE_KEY,
			JSON.stringify([{ requestId: 'ab'.repeat(16), status: 'SIGNED_PENDING' }])
		);
		const store = new DirectFundingPaymentStore({ storage });
		// A record that answers "this request has an attempt" while naming a coin
		// that cannot be re-offered would wedge the request permanently.
		expect(store.restore()).to.equal(0);
	});

	it('never evicts a record whose witness is out', () => {
		const store = new DirectFundingPaymentStore({ storage: memoryStorage() });
		const base = {
			receiptHash: 'cd'.repeat(32),
			receiverNodeId: '02' + 'ab'.repeat(32),
			amountSat: '1000',
			maxTotalFeeSat: '10',
			offerId: 'ef'.repeat(8),
			offerBody: 'aabb',
			spentTxid: '11'.repeat(32),
			spentVout: 0,
			spentValueSat: '2000',
			changeScript: '0014' + '22'.repeat(20),
			createdAt: 0,
			updatedAt: 0
		};
		store.open({
			...base,
			requestId: 'aa'.repeat(16),
			status: 'SIGNED_PENDING'
		});
		store.forget('aa'.repeat(16));
		expect(store.get('aa'.repeat(16))).to.not.equal(null);
		store.open({ ...base, requestId: 'bb'.repeat(16), status: 'CREATED' });
		store.forget('bb'.repeat(16));
		expect(store.get('bb'.repeat(16))).to.equal(null);
	});
});

describe('Direct funding sender: frames that are not ours', () => {
	it('ignores a receipt sealed to nothing we can open', async () => {
		const request = mintRequest();
		const h = harness({ request, receiver: { noReceipt: true } });
		const inner = acceptingReceiver(request, { noReceipt: true });
		const lane = new ScriptedReceiverLane(request, (l, subtype, body): void => {
			inner(l, subtype, body);
			if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_WITNESS) {
				l.replyRaw(
					BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
					crypto.randomBytes(80)
				);
			}
		});
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 150 }
		);
		const result = await sender.send(request.encoded, { amountSat: 100_000n });
		expect(result.receiptPreimageHex).to.equal(null);
	});

	it('ignores a receipt for an offer that is not ours', async () => {
		const request = mintRequest();
		const h = harness({ request, receiver: { noReceipt: true } });
		const inner = acceptingReceiver(request, { noReceipt: true });
		const lane = new ScriptedReceiverLane(request, (l, subtype, body): void => {
			inner(l, subtype, body);
			if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_WITNESS) {
				l.reply(
					BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
					encodeDfReceipt({
						offerId: Buffer.alloc(16, 3),
						preimage: request.preimage,
						fundingTxid: Buffer.alloc(32, 4)
					})
				);
			}
		});
		const sender = new DirectFundingSender(
			{
				wallet: h.wallet,
				registry: registryWith(lane),
				payments: h.payments,
				chainHash: (): Buffer => REGTEST_HASH
			},
			{ offerResendDelaysMs: [], receiptTimeoutMs: 150 }
		);
		const result = await sender.send(request.encoded, { amountSat: 100_000n });
		expect(result.receiptPreimageHex).to.equal(null);
	});

	it('falls through to the next descriptor when a lane never establishes', async () => {
		// The registry's rule, exercised end to end: a lane that put nothing on
		// the wire may be replaced; one that did may not.
		const request = mintRequest({
			transports: [
				{ type: DfTransportType.DIRECT_PEER, host: 'a', port: 1 },
				{ type: DfTransportType.DIRECT_PEER, host: 'b', port: 2 }
			]
		});
		const h = harness({ request, unreachable: true });
		const err = await refusal(
			h.sender.send(request.encoded, { amountSat: 100_000n })
		);
		expect(err.code).to.equal(DirectFundingErrorCode.UNREACHABLE);
		expect(h.payments.list()[0].status).to.equal('ABORTED');
	});
});
