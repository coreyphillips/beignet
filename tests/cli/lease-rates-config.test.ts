/**
 * BEIGNET_LEASE_RATES resolution, offline (issue #532 workstream 1B).
 *
 * The env value is a JSON object of the five option_will_fund lease_rates
 * fields. The rates end up inside a record the node SIGNS, so the fail-closed
 * contract of integerEnv extends to the object: absent stays undefined, but a
 * value that is set and unreadable (malformed JSON, wrong shape, a missing or
 * non-numeric field) surfaces as NaN in the affected fields so daemon startup
 * refuses it by name. It must never resolve to "unset" the way the api-keys
 * env does: a seller policy that silently becomes "never sell" is an
 * operator-visible behavior change with no error.
 */

import { expect } from 'chai';
import { resolveConfig } from '../../src/cli/config';

const VALID = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 10000,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 3
};

describe('resolveConfig leaseRates', () => {
	afterEach(() => {
		delete process.env.BEIGNET_LEASE_RATES;
	});

	it('is undefined when nothing sets it (never sell, the default)', () => {
		const resolved = resolveConfig({});
		expect(resolved.leaseRates).to.equal(undefined);
	});

	it('treats an empty or whitespace value as unset', () => {
		process.env.BEIGNET_LEASE_RATES = '  ';
		const resolved = resolveConfig({});
		expect(resolved.leaseRates).to.equal(undefined);
	});

	it('resolves a valid JSON object to the exact five fields', () => {
		process.env.BEIGNET_LEASE_RATES = JSON.stringify(VALID);
		const resolved = resolveConfig({});
		expect(resolved.leaseRates).to.deep.equal(VALID);
	});

	it('surfaces malformed JSON as NaN fields, not as unset', () => {
		process.env.BEIGNET_LEASE_RATES = '{not json';
		const resolved = resolveConfig({});
		expect(resolved.leaseRates).to.not.equal(undefined);
		for (const value of Object.values(resolved.leaseRates!)) {
			expect(Number.isNaN(value)).to.equal(true);
		}
	});

	it('surfaces a non-object (array, string, number) as NaN fields', () => {
		for (const junk of ['[]', '"rates"', '5', 'null']) {
			process.env.BEIGNET_LEASE_RATES = junk;
			const resolved = resolveConfig({});
			expect(resolved.leaseRates, junk).to.not.equal(undefined);
			for (const value of Object.values(resolved.leaseRates!)) {
				expect(Number.isNaN(value), junk).to.equal(true);
			}
		}
	});

	it('surfaces a missing field as NaN in that field only', () => {
		const partial: Partial<typeof VALID> = { ...VALID };
		delete partial.channelFeeMaxBaseMsat;
		process.env.BEIGNET_LEASE_RATES = JSON.stringify(partial);
		const resolved = resolveConfig({});
		expect(Number.isNaN(resolved.leaseRates!.channelFeeMaxBaseMsat)).to.equal(
			true
		);
		expect(resolved.leaseRates!.fundingWeightWitness).to.equal(1000);
		expect(resolved.leaseRates!.leaseFeeBaseSat).to.equal(10000);
	});

	it('surfaces a non-numeric field as NaN (a typo, not a policy)', () => {
		process.env.BEIGNET_LEASE_RATES = JSON.stringify({
			...VALID,
			leaseFeeBasis: '100'
		});
		const resolved = resolveConfig({});
		expect(Number.isNaN(resolved.leaseRates!.leaseFeeBasis)).to.equal(true);
		expect(resolved.leaseRates!.fundingWeightWitness).to.equal(1000);
	});

	it('prefers the CLI flag over the env var', () => {
		process.env.BEIGNET_LEASE_RATES = JSON.stringify(VALID);
		const flag = { ...VALID, leaseFeeBaseSat: 777 };
		const resolved = resolveConfig({ leaseRates: flag });
		expect(resolved.leaseRates).to.deep.equal(flag);
	});
});
