/**
 * Daemon startup refuses a malformed lease seller policy, and a valid one
 * threads through to the library node (issue #532 workstream 1B).
 *
 * The lease rates are encoded into the SIGNED will_fund record. Three of the
 * five fields are u16 and leaseFeeBaseSat is u32; channelFeeMaxBaseMsat is a
 * tu32 whose encoder silently WRAPS an out-of-range value, meaning the node
 * would sign rates the operator never wrote. So a policy that is set but
 * unreadable refuses startup naming BEIGNET_LEASE_RATES; it must never be
 * silently dropped (a seller becoming "never sell" with no error) or
 * silently clamped.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { startDaemon } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	mnemonic: MNEMONIC,
	daemonPort: 0
};

const VALID = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 10000,
	channelFeeMaxBaseMsat: 5000,
	channelFeeMaxProportionalThousandths: 3
};

async function expectStartRefused(
	opts: Record<string, unknown>,
	message: RegExp
): Promise<void> {
	let error: unknown = null;
	try {
		const daemon = await startDaemon({ ...OFFLINE, ...opts });
		await daemon.stop();
	} catch (e) {
		error = e;
	}
	expect(error, 'expected startDaemon to refuse').to.be.instanceOf(
		BeignetError
	);
	expect((error as BeignetError).code).to.equal('INVALID_PARAMS');
	expect((error as BeignetError).message).to.match(message);
}

describe('daemon startup lease rates', function () {
	this.timeout(30_000);

	it('refuses the NaN-filled object an unparseable env value resolves to', async () => {
		// leaseRatesEnv turns malformed JSON into all-NaN fields; the refusal
		// is what makes that fail closed instead of failing silent.
		const nanFilled = Object.fromEntries(
			Object.keys(VALID).map((k) => [k, Number.NaN])
		);
		await expectStartRefused(
			{ leaseRates: nanFilled },
			/BEIGNET_LEASE_RATES fundingWeightWitness must be an integer/
		);
	});

	it('refuses a non-object policy', async () => {
		await expectStartRefused(
			{ leaseRates: 'sell cheap' },
			/BEIGNET_LEASE_RATES must be a JSON object/
		);
	});

	it('refuses a u16 field past its wire width', async () => {
		await expectStartRefused(
			{ leaseRates: { ...VALID, fundingWeightWitness: 0x1_0000 } },
			/fundingWeightWitness must be an integer between 0 and 65535/
		);
	});

	it('refuses a u32 field past its wire width (the tu32 wrap)', async () => {
		await expectStartRefused(
			{ leaseRates: { ...VALID, channelFeeMaxBaseMsat: 0x1_0000_0000 } },
			/channelFeeMaxBaseMsat must be an integer between 0 and 4294967295/
		);
	});

	it('refuses a fractional field', async () => {
		await expectStartRefused(
			{ leaseRates: { ...VALID, leaseFeeBaseSat: 0.5 } },
			/leaseFeeBaseSat must be an integer/
		);
	});

	it('threads a valid policy and fee trio into the library node', async () => {
		const dataDir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-lease-rates-')
		);
		const daemon = await startDaemon({
			...OFFLINE,
			dataDir,
			routingFeeBaseMsat: 500,
			routingFeePpm: 250,
			routingCltvDelta: 99,
			leaseRates: VALID
		});
		try {
			// The observable ends of the plumbing: the forwarding defaults the
			// node advertises and enforces, and the option_will_fund feature
			// bit that setting a seller policy raises (a CLN buyer refuses to
			// request funds from a peer without it).
			const inner = (daemon.node as unknown as { node: LightningNode }).node;
			const cast = inner as unknown as {
				forwardingFeeBaseMsat: number;
				forwardingFeePropMillionths: number;
				forwardingCltvDelta: number;
				localFeatures: FeatureFlags;
			};
			expect(cast.forwardingFeeBaseMsat).to.equal(500);
			expect(cast.forwardingFeePropMillionths).to.equal(250);
			expect(cast.forwardingCltvDelta).to.equal(99);
			expect(cast.localFeatures.hasFeature(Feature.OPTION_WILL_FUND)).to.equal(
				true
			);
		} finally {
			await daemon.stop();
			fs.rmSync(dataDir, { recursive: true, force: true });
		}
	});
});
