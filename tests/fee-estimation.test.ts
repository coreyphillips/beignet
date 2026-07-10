import { expect } from 'chai';
import {
	btcPerKbToSatPerVbyte,
	clampFeeRate,
	EAvailableNetworks,
	err,
	IOnchainFees,
	MAX_FEE_RATE_SAT_PER_VBYTE,
	ok,
	Result,
	Wallet
} from '../src';

/**
 * These tests run fully offline: they exercise the fee-source selection logic
 * on a bare object carrying Wallet.prototype, with the Electrum client and
 * global fetch stubbed out.
 */

const previousFees: IOnchainFees = {
	fast: 4,
	normal: 3,
	slow: 2,
	minimum: 1,
	timestamp: 0
};

// BTC/kB values as returned by blockchain.estimatefee.
const electrumResponses: { [blocks: number]: number } = {
	2: 0.0002, // 20 sat/vB
	6: 0.0001, // 10 sat/vB
	24: 0.00005, // 5 sat/vB
	144: 0.00001 // 1 sat/vB
};

const mempoolPayload = {
	fastestFee: 40,
	halfHourFee: 30,
	hourFee: 20,
	minimumFee: 10
};

interface IFakeWalletOptions {
	source: 'electrum' | 'http' | 'auto';
	connected?: boolean;
	estimate?: (blocks: number) => Promise<Result<number>>;
	network?: EAvailableNetworks;
}

// Builds a minimal object that behaves like a Wallet for fee estimation only.
const fakeWallet = ({
	source,
	connected = true,
	estimate = async (blocks): Promise<Result<number>> =>
		ok(btcPerKbToSatPerVbyte(electrumResponses[blocks])),
	network = EAvailableNetworks.bitcoin
}: IFakeWalletOptions): Wallet => {
	const wallet = Object.create(Wallet.prototype);
	wallet._network = network;
	wallet.feeEstimationSource = source;
	wallet.feeEstimates = { ...previousFees };
	wallet.electrum = {
		connectedToElectrum: connected,
		getFeeEstimate: estimate
	};
	return wallet;
};

describe('Fee estimation source selection', () => {
	const originalFetch = global.fetch;
	let fetchCalls: string[] = [];

	const stubFetch = (payload: unknown): void => {
		global.fetch = (async (url: string) => {
			fetchCalls.push(String(url));
			return { json: async (): Promise<unknown> => payload };
		}) as typeof fetch;
	};

	beforeEach(() => {
		fetchCalls = [];
		stubFetch(mempoolPayload);
	});

	afterEach(() => {
		global.fetch = originalFetch;
	});

	describe('btcPerKbToSatPerVbyte conversion', () => {
		it('converts BTC/kB to sat/vB', () => {
			expect(btcPerKbToSatPerVbyte(0.0001)).to.equal(10);
			expect(btcPerKbToSatPerVbyte(0.00001)).to.equal(1);
		});

		it('floors fractional results', () => {
			expect(btcPerKbToSatPerVbyte(0.000025)).to.equal(2);
		});

		it('floors positive sub-1 rates to 1', () => {
			expect(btcPerKbToSatPerVbyte(0.000001)).to.equal(1);
		});

		it('returns 0 for -1 (no estimate available)', () => {
			expect(btcPerKbToSatPerVbyte(-1)).to.equal(0);
		});

		it('returns 0 for zero and non-finite input', () => {
			expect(btcPerKbToSatPerVbyte(0)).to.equal(0);
			expect(btcPerKbToSatPerVbyte(NaN)).to.equal(0);
			expect(btcPerKbToSatPerVbyte(Infinity)).to.equal(0);
		});

		it('clamps absurd rates to the maximum', () => {
			// 1 BTC/kB = 100000 sat/vB
			expect(btcPerKbToSatPerVbyte(1)).to.equal(MAX_FEE_RATE_SAT_PER_VBYTE);
		});
	});

	describe('clampFeeRate', () => {
		it('caps rates above the maximum', () => {
			expect(clampFeeRate(MAX_FEE_RATE_SAT_PER_VBYTE + 1)).to.equal(
				MAX_FEE_RATE_SAT_PER_VBYTE
			);
		});

		it('floors positive sub-1 rates to 1', () => {
			expect(clampFeeRate(0.5)).to.equal(1);
		});

		it('floors fractional rates', () => {
			expect(clampFeeRate(10.9)).to.equal(10);
		});

		it('returns 0 for unusable rates', () => {
			expect(clampFeeRate(0)).to.equal(0);
			expect(clampFeeRate(-3)).to.equal(0);
			expect(clampFeeRate(NaN)).to.equal(0);
			expect(clampFeeRate(Infinity)).to.equal(0);
		});
	});

	describe("source 'auto'", () => {
		it('uses Electrum when connected and usable, without HTTP', async () => {
			const wallet = fakeWallet({ source: 'auto' });
			const fees = await wallet.getFeeEstimates();
			expect(fees.fast).to.equal(20);
			expect(fees.normal).to.equal(10);
			expect(fees.slow).to.equal(5);
			expect(fees.minimum).to.equal(1);
			expect(fetchCalls).to.have.length(0);
		});

		it('falls back to HTTP when Electrum is disconnected', async () => {
			const wallet = fakeWallet({ source: 'auto', connected: false });
			const fees = await wallet.getFeeEstimates();
			expect(fees.fast).to.equal(mempoolPayload.fastestFee);
			expect(fees.normal).to.equal(mempoolPayload.halfHourFee);
			expect(fees.slow).to.equal(mempoolPayload.hourFee);
			expect(fees.minimum).to.equal(mempoolPayload.minimumFee);
			expect(fetchCalls).to.have.length(1);
		});

		it('falls back to HTTP when Electrum returns unusable values', async () => {
			const wallet = fakeWallet({
				source: 'auto',
				estimate: async (): Promise<Result<number>> =>
					err('estimatefee returned -1')
			});
			const fees = await wallet.getFeeEstimates();
			expect(fees.fast).to.equal(mempoolPayload.fastestFee);
			expect(fetchCalls).to.have.length(1);
		});

		it('clamps absurd Electrum-sourced values', async () => {
			const wallet = fakeWallet({
				source: 'auto',
				estimate: async (): Promise<Result<number>> =>
					ok(btcPerKbToSatPerVbyte(2)) // 200000 sat/vB before clamp
			});
			const fees = await wallet.getFeeEstimates();
			expect(fees.fast).to.equal(MAX_FEE_RATE_SAT_PER_VBYTE);
			expect(fees.minimum).to.equal(MAX_FEE_RATE_SAT_PER_VBYTE);
			expect(fetchCalls).to.have.length(0);
		});
	});

	describe("source 'electrum'", () => {
		it('never falls back to HTTP; returns previous estimates on failure', async () => {
			const wallet = fakeWallet({ source: 'electrum', connected: false });
			const fees = await wallet.getFeeEstimates();
			expect(fees).to.deep.equal(previousFees);
			expect(fetchCalls).to.have.length(0);
		});

		it('uses Electrum values when available', async () => {
			const wallet = fakeWallet({ source: 'electrum' });
			const fees = await wallet.getFeeEstimates();
			expect(fees.fast).to.equal(20);
			expect(fetchCalls).to.have.length(0);
		});
	});

	describe("source 'http'", () => {
		it('skips Electrum entirely', async () => {
			let electrumCalled = false;
			const wallet = fakeWallet({
				source: 'http',
				estimate: async (): Promise<Result<number>> => {
					electrumCalled = true;
					return ok(20);
				}
			});
			const fees = await wallet.getFeeEstimates();
			expect(electrumCalled).to.equal(false);
			expect(fees.fast).to.equal(mempoolPayload.fastestFee);
			expect(fetchCalls).to.have.length(1);
		});

		it('clamps absurd HTTP-sourced values', async () => {
			stubFetch({
				fastestFee: 1e6,
				halfHourFee: 30,
				hourFee: 20,
				minimumFee: 10
			});
			const wallet = fakeWallet({ source: 'http' });
			const fees = await wallet.getFeeEstimates();
			expect(fees.fast).to.equal(MAX_FEE_RATE_SAT_PER_VBYTE);
			expect(fees.normal).to.equal(30);
		});

		it('uses the signet mempool.space endpoint on signet', async () => {
			const wallet = fakeWallet({
				source: 'http',
				network: EAvailableNetworks.signet
			});
			await wallet.getFeeEstimates();
			expect(fetchCalls[0]).to.include('mempool.space/signet/');
		});
	});

	it('returns default estimates on regtest without any remote call', async () => {
		const wallet = fakeWallet({
			source: 'auto',
			network: EAvailableNetworks.regtest
		});
		const fees = await wallet.getFeeEstimates();
		expect(fees.minimum).to.be.greaterThan(0);
		expect(fetchCalls).to.have.length(0);
	});
});
