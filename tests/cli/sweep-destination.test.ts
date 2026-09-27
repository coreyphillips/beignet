/**
 * Force-close sweep destination resolution.
 *
 * A remote force-close detected at startup gets its to_local/to_remote swept to
 * `getSweepDestinationScript()`. When the wallet sweep address is undefined that
 * resolves to the funding-key P2WPKH fallback, an address the on-chain wallet
 * does NOT scan, leaving recovered sats confirmed but invisible until a later
 * recoverFallbackFunds pass.
 *
 * resolveWalletSweepScript() must therefore ALWAYS yield a wallet-owned address:
 * the preferred unused-address lookup needs Electrum, but it must fall back to
 * the wallet's stored change address (network-free) so a force-close detected
 * while Electrum is still connecting never pins the sweep to the invisible
 * fallback.
 *
 * And every leg must yield a CHANGE address, never a receive address (issue
 * #1064). The next unused receive address is exactly the one getNewAddress /
 * POST /address/new handed out most recently and a saved receive request still
 * holds, so a payout there read as the payer paying that request: wallet-core
 * marked the request partly paid and dropped the payout's own row. No request
 * or route ever hands out a change address. The startup sweep script, the
 * background refresh, the force close and the FFOR enforce all consume the
 * same resolution, so each is pinned here.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import sinon from 'sinon';
import { BeignetNode } from '../../src/cli/beignet-node';

const NETWORK = bitcoin.networks.bitcoin;
const p2wpkh = (fill: number): string =>
	bitcoin.payments.p2wpkh({ hash: Buffer.alloc(20, fill), network: NETWORK })
		.address!;
// The next unused RECEIVE address: the one a payer was most recently given.
const RECEIVE_ADDR = p2wpkh(1);
// The next unused CHANGE address the same gap scan returns.
const CHANGE_ADDR = p2wpkh(2);
// The wallet's stored change address (getChangeAddress, no network needed).
const STORED_CHANGE_ADDR = p2wpkh(3);
// Receive index 0, the leg issue #1064 removed.
const INDEX0_ADDR = p2wpkh(4);
const CHANNEL_ID = 'ab'.repeat(32);

const scriptOf = (addr: string): Buffer =>
	bitcoin.address.toOutputScript(addr, NETWORK);

/**
 * sinon's fake timers, reached through a cast (the wallet-create-error idiom):
 * the sinon typing this repo resolves for the default export does not declare
 * them. Intervals only: promises and setImmediate stay real, so awaits run.
 */
type TFakeClock = {
	tickAsync: (ms: number) => Promise<void>;
	restore: () => void;
};
const useFakeClock = (): TFakeClock =>
	(
		sinon as unknown as {
			useFakeTimers: (opts: { toFake: string[] }) => TFakeClock;
		}
	).useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });

function fakeNode(wallet: any, extra: Record<string, unknown> = {}): any {
	// Inherit the prototype (the funding-refusal-statuses idiom):
	// resolveWalletSweepScript delegates to another private method since
	// issue #542, so a bare literal `this` no longer resolves it.
	return Object.assign(Object.create(BeignetNode.prototype), {
		wallet,
		networkName: 'bitcoin',
		getBitcoinNetwork: () => NETWORK,
		log: () => undefined,
		...extra
	});
}

function callResolve(wallet: any): Promise<Buffer | undefined> {
	return fakeNode(wallet).resolveWalletSweepScript();
}

/** getNextAvailableAddress as the wallet answers it: BOTH chains. */
const okResult = (
	receive: string = RECEIVE_ADDR,
	change: string = CHANGE_ADDR
): any => ({
	isOk: () => true,
	isErr: () => false,
	value: {
		addressIndex: { address: receive, index: 7 },
		lastUsedAddressIndex: { address: p2wpkh(9), index: 6 },
		changeAddressIndex: { address: change, index: 3 },
		lastUsedChangeAddressIndex: { address: p2wpkh(10), index: 2 }
	}
});
const errResult = (): any => ({
	isOk: () => false,
	isErr: () => true,
	error: { message: 'electrum not connected' }
});
const okChange = (address: string = STORED_CHANGE_ADDR): any => ({
	isOk: () => true,
	isErr: () => false,
	value: { address, index: 3 }
});
const notReached = (what: string) => async (): Promise<never> => {
	throw new Error(`${what} should not be reached`);
};

/** A wallet whose Electrum gap scan works. */
const onlineWallet = (): any => ({
	getNextAvailableAddress: async () => okResult(),
	getChangeAddress: notReached('getChangeAddress (the stored-change leg)'),
	getAddress: notReached('getAddress (the removed receive index 0 leg)')
});

describe('Force-close sweep destination resolution', () => {
	it('pays the next unused CHANGE address when Electrum is available, never the receive address (issue #1064)', async () => {
		const script = await callResolve(onlineWallet());
		expect(script).to.deep.equal(scriptOf(CHANGE_ADDR));
		expect(script!.equals(scriptOf(RECEIVE_ADDR))).to.equal(false);
	});

	it('the address a payer was given (getNewAddress) is never the sweep destination', async () => {
		// The bug: a receive request's address IS the next unused receive
		// address until it is paid, so the old resolution swept the close
		// into it and the request read as partly paid.
		const bn = fakeNode(onlineWallet());
		const handedOut: string = await bn.getNewAddress();
		expect(handedOut).to.equal(RECEIVE_ADDR);
		const script = await bn.resolveWalletSweepScript();
		expect(script).to.not.be.undefined;
		expect(script!.equals(scriptOf(handedOut))).to.equal(false);
		expect(script).to.deep.equal(scriptOf(CHANGE_ADDR));
	});

	it('falls back to the stored change address when the unused lookup fails (Electrum down)', async () => {
		let storedChangeReads = 0;
		const wallet = {
			getNextAvailableAddress: async () => errResult(),
			getChangeAddress: async () => {
				storedChangeReads++;
				return okChange();
			},
			// Receive index 0 was the old offline leg: a receive address the
			// upstream POST /address/new hands out on a new wallet.
			getAddress: notReached('getAddress (the removed receive index 0 leg)')
		};
		const script = await callResolve(wallet);
		// The whole point: a wallet-owned script is still returned, so the sweep
		// never targets the invisible funding-key fallback, and it is the
		// change chain, so it can never be a request's address.
		expect(script).to.deep.equal(scriptOf(STORED_CHANGE_ADDR));
		expect(script!.equals(scriptOf(INDEX0_ADDR))).to.equal(false);
		expect(storedChangeReads).to.equal(1);
	});

	it('falls back to the stored change address when the unused lookup throws', async () => {
		const wallet = {
			getNextAvailableAddress: async () => {
				throw new Error('electrum timeout');
			},
			getChangeAddress: async () => okChange(),
			getAddress: async () => INDEX0_ADDR
		};
		const script = await callResolve(wallet);
		expect(script).to.deep.equal(scriptOf(STORED_CHANGE_ADDR));
	});

	it('returns undefined only when both the unused lookup AND the stored change address fail', async () => {
		const errs = {
			getNextAvailableAddress: async () => errResult(),
			getChangeAddress: async () => ({
				isOk: () => false,
				isErr: () => true,
				error: { message: 'Unable to successfully generate a change address.' }
			}),
			// Even with receive index 0 derivable: it is not a leg any more.
			getAddress: async () => INDEX0_ADDR
		};
		expect(await callResolve(errs)).to.be.undefined;
		const throws = {
			...errs,
			getChangeAddress: async () => {
				throw new Error('wallet locked');
			}
		};
		expect(await callResolve(throws)).to.be.undefined;
	});

	it('the startup resolution (bounded, as initNode runs it) yields the change address', async () => {
		const bn = fakeNode(onlineWallet());
		const script: Buffer | undefined = await bn.raceWithTimeout(
			bn.resolveWalletSweepScript().catch(() => undefined),
			(BeignetNode as any).STARTUP_ADDRESS_LOOKUP_TIMEOUT_MS
		);
		expect(script).to.deep.equal(scriptOf(CHANGE_ADDR));
	});

	it('the background refresh redirects sweeps to the change address', async () => {
		// Electrum was down at startup: the refresh keeps retrying and, once
		// the gap scan answers, redirects every pending and future sweep.
		const clock = useFakeClock();
		try {
			let engineScript: Buffer | undefined;
			let calls = 0;
			const bn = fakeNode(
				{
					getNextAvailableAddress: async () =>
						++calls === 1 ? errResult() : okResult(),
					getChangeAddress: async () => errResult(),
					getAddress: notReached('getAddress')
				},
				{
					node: {
						setSweepDestinationScript: (script: Buffer) => {
							engineScript = script;
						}
					},
					recoverFallbackFunds: async () => undefined
				}
			);
			bn.scheduleSweepAddressRefresh();
			await clock.tickAsync(5000);
			expect(engineScript, 'first tick: still offline').to.be.undefined;
			await clock.tickAsync(5000);
			expect(engineScript).to.deep.equal(scriptOf(CHANGE_ADDR));
			expect(bn.sweepDestinationScript).to.deep.equal(scriptOf(CHANGE_ADDR));
			expect(bn._sweepRefreshTimer, 'stops on success').to.be.undefined;
		} finally {
			clock.restore();
		}
	});

	it('the force close and the FFOR enforce pay the resolved change address', async () => {
		let forced: Buffer | undefined;
		const bn = fakeNode(onlineWallet(), {
			node: {
				getChannel: () => ({ channelId: Buffer.from(CHANNEL_ID, 'hex') }),
				getRecoveryStatus: () => ({ channels: [] }),
				getRecoveryOwnershipHold: () => null,
				getChannelManager: () => ({ getChannel: () => undefined }),
				getFundingAddress: () => p2wpkh(5),
				forceCloseChannel: (_id: Buffer, script: Buffer) => {
					forced = script;
					return { ok: true, commitmentTxid: 'aa'.repeat(32) };
				}
			}
		});
		// As initNode does: resolve once at startup, then every sweep uses it.
		bn.sweepDestinationScript = await bn.resolveWalletSweepScript();
		const result = bn.forceCloseChannel(CHANNEL_ID);
		expect(result.ok).to.equal(true);
		expect(forced).to.deep.equal(scriptOf(CHANGE_ADDR));
		expect(forced!.equals(scriptOf(RECEIVE_ADDR))).to.equal(false);
		expect(bn.fforDestinationScript()).to.deep.equal(scriptOf(CHANGE_ADDR));
	});
});
