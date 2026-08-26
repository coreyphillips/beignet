/**
 * Daemon startup refuses out-of-range routing fee defaults (issue #532
 * workstream 1B).
 *
 * channel_update carries fee_base_msat and fee_proportional_millionths as u32
 * and cltv_expiry_delta as u16 (BOLT 7). A value the wire cannot hold would
 * wrap into an advertised policy the operator never wrote, or throw only once
 * gossip is being rebuilt, so the daemon refuses it before the node exists,
 * naming the env var. integerEnv hands partially numeric env values over as
 * NaN, which the same checks catch.
 */

import { expect } from 'chai';
import { startDaemon } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';

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

describe('daemon startup routing fee refusals', function () {
	this.timeout(30_000);

	it('refuses an unparseable or out-of-range base fee naming the env var', async () => {
		for (const bad of [Number.NaN, -1, 1.5, 0x1_0000_0000]) {
			await expectStartRefused(
				{ routingFeeBaseMsat: bad },
				/BEIGNET_FEE_BASE_MSAT must be an integer between 0 and 4294967295/
			);
		}
	});

	it('refuses an unparseable or out-of-range proportional fee', async () => {
		for (const bad of [Number.NaN, -1, 1.5, 0x1_0000_0000]) {
			await expectStartRefused(
				{ routingFeePpm: bad },
				/BEIGNET_FEE_PPM must be an integer between 0 and 4294967295/
			);
		}
	});

	it('refuses a CLTV delta outside u16, zero included', async () => {
		// Zero would leave no window to claim a forwarded HTLC on-chain after
		// learning the preimage, so the floor is 1 as on the per-channel
		// update-policy surface.
		for (const bad of [Number.NaN, 0, -1, 1.5, 0x1_0000]) {
			await expectStartRefused(
				{ routingCltvDelta: bad },
				/BEIGNET_CLTV_DELTA must be an integer between 1 and 65535/
			);
		}
	});
});
