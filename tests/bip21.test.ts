import { expect } from 'chai';
import {
	EAvailableNetworks,
	encodeBip21,
	parseOnChainPaymentRequest
} from '../src';

const address = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';

const encode = (params: Parameters<typeof encodeBip21>[0]): string => {
	const res = encodeBip21(params);
	if (res.isErr()) throw res.error;
	return res.value;
};

describe('BIP21 URI generation', () => {
	it('encodes an address with no params', () => {
		expect(encode({ address })).to.equal(`bitcoin:${address}`);
	});

	it('encodes the amount in BTC decimal', () => {
		expect(encode({ address, amountSats: 123456789 })).to.equal(
			`bitcoin:${address}?amount=1.23456789`
		);
	});

	it('never serializes small amounts in exponent form', () => {
		expect(encode({ address, amountSats: 1 })).to.equal(
			`bitcoin:${address}?amount=0.00000001`
		);
	});

	it('trims trailing zeros from round amounts', () => {
		expect(encode({ address, amountSats: 10000000 })).to.equal(
			`bitcoin:${address}?amount=0.1`
		);
		expect(encode({ address, amountSats: 100000000 })).to.equal(
			`bitcoin:${address}?amount=1`
		);
	});

	it('encodes label and message', () => {
		const uri = encode({
			address,
			amountSats: 5000,
			label: 'Luke Jr',
			message: 'Donation for project xyz'
		});
		expect(uri).to.include('label=Luke%20Jr');
		expect(uri).to.include('message=Donation%20for%20project%20xyz');
	});

	it('round-trips through the existing decoder', () => {
		const uri = encode({
			address,
			amountSats: 123456789,
			message: 'hello world'
		});
		const decoded = parseOnChainPaymentRequest(uri, EAvailableNetworks.bitcoin);
		if (decoded.isErr()) throw decoded.error;
		expect(decoded.value.address).to.equal(address);
		expect(decoded.value.sats).to.equal(123456789);
		expect(decoded.value.message).to.equal('hello world');
	});

	it('round-trips a 1 sat amount without precision loss', () => {
		const uri = encode({ address, amountSats: 1 });
		const decoded = parseOnChainPaymentRequest(uri, EAvailableNetworks.bitcoin);
		if (decoded.isErr()) throw decoded.error;
		expect(decoded.value.sats).to.equal(1);
	});

	it('round-trips a large amount without precision loss', () => {
		const amountSats = 2099999997690000; // 21M BTC minus dust, in sats
		const uri = encode({ address, amountSats });
		const decoded = parseOnChainPaymentRequest(uri, EAvailableNetworks.bitcoin);
		if (decoded.isErr()) throw decoded.error;
		expect(decoded.value.sats).to.equal(amountSats);
	});

	it('round-trips a no-params URI', () => {
		const uri = encode({ address });
		const decoded = parseOnChainPaymentRequest(uri, EAvailableNetworks.bitcoin);
		if (decoded.isErr()) throw decoded.error;
		expect(decoded.value.address).to.equal(address);
		expect(decoded.value.sats).to.equal(0);
	});

	it('omits a zero amount', () => {
		expect(encode({ address, amountSats: 0 })).to.equal(`bitcoin:${address}`);
	});

	it('rejects a missing address', () => {
		expect(encodeBip21({ address: '' }).isErr()).to.equal(true);
	});

	it('rejects negative and non-integer amounts', () => {
		expect(encodeBip21({ address, amountSats: -1 }).isErr()).to.equal(true);
		expect(encodeBip21({ address, amountSats: 1.5 }).isErr()).to.equal(true);
	});
});
