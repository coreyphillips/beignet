import { expect } from 'chai';
import {
	DirectFundingClient,
	IDirectFundingWallet,
	parseDirectFundingRequest
} from '../../src/direct-funding/client';
import { Network } from '../../src/lightning/invoice/types';
import { DF_PAYMENTS_STORAGE_KEY } from '../../src/lightning/direct-funding/sender/records';
import {
	FakeSenderWallet,
	ScriptedReceiverLane,
	acceptingReceiver,
	makeCoin,
	memoryStorage,
	mintRequest,
	registryWith
} from '../lightning/helpers/df-sender';

async function refuses(
	promise: Promise<unknown>,
	message: string
): Promise<void> {
	let error: unknown;
	try {
		await promise;
	} catch (err) {
		error = err;
	}
	expect(error).to.be.instanceOf(Error);
	expect((error as Error).message).to.include(message);
}

function setup(noReceipt = false, amountSat: bigint | undefined = 100_000n) {
	const request = mintRequest({ amountSat });
	const wallet: FakeSenderWallet & IDirectFundingWallet = Object.assign(
		new FakeSenderWallet([makeCoin()]),
		{ network: Network.REGTEST }
	);
	const storage = memoryStorage();
	let witnesses = 0;
	const lane = new ScriptedReceiverLane(
		request,
		acceptingReceiver(request, {
			noReceipt,
			onWitness: () => {
				witnesses++;
			}
		})
	);
	const registry = registryWith(lane);
	const options = {
		wallet,
		storage,
		registry,
		network: Network.REGTEST,
		config: {
			offerResendDelaysMs: [],
			offerTimeoutMs: 1_000,
			receiptTimeoutMs: 10
		}
	};
	const client = new DirectFundingClient(options);
	return {
		request,
		wallet,
		storage,
		options,
		client,
		lane,
		witnesses: () => witnesses
	};
}

describe('Direct-funding payer SDK', () => {
	it('rejects a client configured for a different wallet network', () => {
		const s = setup();
		expect(
			() => new DirectFundingClient({ ...s.options, network: Network.MAINNET })
		).to.throw('wallet network does not match');
	});
	it('inspects without touching wallet, transport or storage', () => {
		const s = setup();
		s.wallet.refresh = async () => {
			throw new Error('must not refresh');
		};
		const info = s.client.inspect(s.request.encoded);
		expect(info.envelope.amountSat).to.equal(100_000n);
		expect(s.lane.sent).to.have.length(0);
		expect(s.storage.rows.size).to.equal(0);
	});

	it('pays a URI once and joins concurrent calls before wallet refresh', async () => {
		const s = setup();
		let refreshes = 0;
		s.wallet.refresh = async () => {
			refreshes++;
		};
		const uri = `bitcoin:unused?amount=0.001&bgnq=${s.request.encoded}`;
		const first = s.client.pay(uri);
		const second = s.client.pay(uri);
		expect(first).to.equal(second);
		const paid = await first;
		expect(paid.attested).to.equal(true);
		expect(paid.receiptPreimageHex).to.equal(
			s.request.preimage.toString('hex')
		);
		expect(s.witnesses()).to.equal(1);
		expect(refreshes).to.equal(1);
	});

	it('uses an exact URI amount when the signed request has no amount', async () => {
		const s = setup(false, undefined);
		// setup defaults are fixed, so mint an amountless request explicitly.
		const request = mintRequest();
		const lane = new ScriptedReceiverLane(request, acceptingReceiver(request));
		const client = new DirectFundingClient({
			...s.options,
			registry: registryWith(lane)
		});
		const paid = await client.pay(
			`bitcoin:unused?amount=0.00100001&bgnq=${request.encoded}`
		);
		expect(paid.amountSat).to.equal(100_001);
	});

	it('refuses conflicting URI and signed amounts before any offer', async () => {
		const s = setup();
		await refuses(
			s.client.pay(`bitcoin:unused?amount=0.002&bgnq=${s.request.encoded}`),
			'differs'
		);
		expect(s.lane.sent).to.have.length(0);
	});

	it('returns pending on receipt timeout and keeps its reservation', async () => {
		const s = setup(true);
		const paid = await s.client.pay(s.request.encoded);
		expect(paid.status).to.equal('SIGNED_PENDING');
		expect(paid.receiptPreimageHex).to.equal(null);
		expect(s.wallet.frozen.size).to.equal(1);
		expect(s.witnesses()).to.equal(1);
	});

	it('restores signed payments and replays without signing or refreshing again', async () => {
		const s = setup(true);
		const first = await s.client.pay(s.request.encoded);
		s.wallet.refresh = async () => {
			throw new Error('offline');
		};
		const restarted = new DirectFundingClient(s.options);
		const replay = await restarted.pay(
			`bitcoin:unused?amount=0.002&bgnq=${s.request.encoded}`
		);
		expect(replay.fundingTxid).to.equal(first.fundingTxid);
		expect(replay.amountSat).to.equal(first.amountSat);
		expect(replay.status).to.equal('SIGNED_PENDING');
		expect(s.witnesses()).to.equal(1);
	});

	it('supplies funding ids before reconciliation and advances to confirmed', async () => {
		const s = setup(true);
		const paid = await s.client.pay(s.request.encoded);
		s.wallet.refresh = async (ids) => {
			expect(ids).to.deep.equal([paid.fundingTxid]);
			s.wallet.known.set(paid.fundingTxid!, true);
		};
		await s.client.reconcile();
		expect(s.client.payments()[0].status).to.equal('CONFIRMED');
	});

	it('does not expose mutable journal records', async () => {
		const s = setup();
		await s.client.pay(s.request.encoded);
		const rows = s.client.payments();
		rows[0].status = 'ABORTED';
		rows[0].witness![0] = '00';
		expect(s.client.payments()[0].status).not.to.equal('ABORTED');
		expect(s.client.payments()[0].witness![0]).not.to.equal('00');
	});

	it('refuses request id reuse with a different signed receiver', async () => {
		const s = setup();
		await s.client.pay(s.request.encoded);
		const replacement = mintRequest({
			requestId: s.request.requestId,
			amountSat: 100_000n
		});
		await refuses(s.client.pay(replacement.encoded), 'already bound');
		expect(s.witnesses()).to.equal(1);
	});

	it('binds a request id before asynchronous wallet refresh can create a record', async () => {
		const s = setup();
		let release!: () => void;
		const waiting = new Promise<void>((resolve) => {
			release = resolve;
		});
		s.wallet.refresh = () => waiting;
		const payment = s.client.pay(s.request.encoded);
		const replacement = mintRequest({
			requestId: s.request.requestId,
			amountSat: 100_000n
		});
		await refuses(s.client.pay(replacement.encoded), 'already bound');
		release();
		await payment;
		expect(s.witnesses()).to.equal(1);
	});

	it('refuses corrupt and incomplete signed journals instead of forgetting payments', async () => {
		const s = setup();
		s.storage.rows.set(DF_PAYMENTS_STORAGE_KEY, '{');
		expect(() => new DirectFundingClient(s.options)).to.throw('corrupt');
		s.storage.rows.clear();
		await s.client.pay(s.request.encoded);
		const rows = s.client.payments();
		rows[0].witness = ['xyz'];
		s.storage.rows.set(DF_PAYMENTS_STORAGE_KEY, JSON.stringify(rows));
		expect(() => new DirectFundingClient(s.options)).to.throw(
			'valid signed commitment'
		);
	});

	it('withholds the funding witness when durability fails', async () => {
		const s = setup();
		s.storage.failWhen = (value) => value.includes('SIGNED_PENDING');
		await refuses(s.client.pay(s.request.encoded), 'persist');
		expect(s.witnesses()).to.equal(0);
	});

	it('refuses async storage even when a void signature permits it', async () => {
		const s = setup();
		const storage = {
			loadWalletData: () => null,
			saveWalletData: async () => {
				throw new Error('async write failed');
			}
		};
		const client = new DirectFundingClient({ ...s.options, storage });
		await refuses(client.pay(s.request.encoded), 'persist');
		expect(s.lane.sent).to.have.length(0);
	});

	it('rejects malformed requests through a promise', async () => {
		const s = setup();
		let result: Promise<unknown> | undefined;
		expect(() => {
			result = s.client.pay('bitcoin:address');
		}).not.to.throw();
		await refuses(result!, 'no bgnq');
	});

	it('rejects wrong network and expired requests before contacting a wallet', async () => {
		const s = setup();
		await refuses(
			s.client.pay(mintRequest({ network: Network.MAINNET }).encoded),
			'different chain'
		);
		await refuses(
			s.client.pay(mintRequest({ now: Date.now() - 10_000, ttlMs: 1 }).encoded),
			'expired'
		);
		expect(s.lane.sent).to.have.length(0);
	});
});

describe('Direct-funding URI parsing', () => {
	for (const uri of [
		'bitcoin:x?bgnq=a&bgnq=b',
		'bitcoin:x?bgnq=a&%62gnq=b',
		'bitcoin:x?bgnq=a&amount=1&amount=2',
		'bitcoin:x?bgnq=a&amount=0.000000001',
		'bitcoin:x?bgnq=a&amount=1e-8',
		'bitcoin:x?bgnq=a&req-unknown=1',
		'bitcoin:x?bgnq=a#fragment',
		'bitcoin:x?bgnq=%xx',
		'bitcoin:x?amount=1'
	]) {
		it(`refuses ${uri}`, () => {
			expect(() => parseDirectFundingRequest(uri)).to.throw();
		});
	}
	it('handles scheme case and exact decimal satoshis', () => {
		expect(
			parseDirectFundingRequest('BITCOIN:x?bgnq=abc&amount=0.00000001')
		).to.deep.equal({ encoded: 'abc', uriAmountSat: 1n });
	});
});
