/**
 * Cooperative-close payout destination (issue #542, LFBW port #532
 * workstream 1C; issue #1064 for the chain it pays).
 *
 * closeChannel pays the mutual-close output to an address the on-chain
 * wallet actually scans: the next unused CHANGE address first (a BOUNDED
 * lookup, because it can enter an Electrum handshake with no timeout of its
 * own and the close must reach the engine regardless), then the sweep script
 * resolved at startup, and only then the funding-key P2WPKH the old behavior
 * always paid, which recoverFallbackFunds can still rescue. Every leg is
 * derived locally from our own keys, so the chain always terminates in a
 * script we control.
 *
 * The change chain, never the receive chain (issue #1064): the next unused
 * receive address is the one getNewAddress / POST /address/new handed out
 * most recently and a saved receive request still holds, so a payout there
 * read as the payer paying that request (wallet-core marked it partly paid
 * and dropped the payout's own row). No request or route ever hands out a
 * change address. The offline leg the force-close startup resolution uses
 * (the stored change address; receive index 0 before #1064) is deliberately
 * NOT in this chain: index 0 could sit outside the 20-address scan window
 * with nothing to rescue it (issue #542 review), and the startup script
 * already covers an Electrum outage at close time.
 *
 * Engine-stub harness (the funding-refusal-statuses idiom): the captured
 * scriptPubkey handed to the library close IS the observable.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetNode } from '../../src/cli/beignet-node';

const CHANNEL_ID = 'cd'.repeat(32);
const p2wpkh = (fill: number): string =>
	bitcoin.payments.p2wpkh({
		hash: Buffer.alloc(20, fill),
		network: bitcoin.networks.regtest
	}).address!;
// The next unused RECEIVE address: the one a payer was most recently given.
const RECEIVE_ADDR = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';
// The next unused CHANGE address the same gap scan returns.
const CHANGE_ADDR = p2wpkh(1);
// The wallet's stored change address (the force-close offline leg).
const STORED_CHANGE_ADDR = p2wpkh(2);
const INDEX0_ADDR =
	'bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry';
const FUNDING_ADDR = p2wpkh(7);

const scriptOf = (addr: string): Buffer =>
	bitcoin.address.toOutputScript(addr, bitcoin.networks.regtest);

/** getNextAvailableAddress as the wallet answers it: BOTH chains. */
const bothChains = (): unknown => ({
	isOk: (): boolean => true,
	isErr: (): boolean => false,
	value: {
		addressIndex: { address: RECEIVE_ADDR, index: 7 },
		lastUsedAddressIndex: { address: p2wpkh(8), index: 6 },
		changeAddressIndex: { address: CHANGE_ADDR, index: 3 },
		lastUsedChangeAddressIndex: { address: p2wpkh(9), index: 2 }
	}
});
const storedChange = (): unknown => ({
	isOk: (): boolean => true,
	isErr: (): boolean => false,
	value: { address: STORED_CHANGE_ADDR, index: 3 }
});

interface ICloseCapture {
	script?: Buffer;
	acceptStaleStateRisk?: boolean;
}

function closableNode(opts: {
	wallet: Record<string, unknown>;
	sweepDestinationScript?: Buffer;
	capture: ICloseCapture;
	lookupTimeoutMs?: number;
}): BeignetNode {
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: {
			getChannel: (): unknown => ({ channelId: Buffer.alloc(32) }),
			getFundingAddress: (): string => FUNDING_ADDR,
			closeChannel: (
				_id: Buffer,
				script: Buffer,
				acceptStaleStateRisk: boolean
			): unknown => {
				opts.capture.script = script;
				opts.capture.acceptStaleStateRisk = acceptStaleStateRisk;
				return { ok: true };
			}
		},
		networkName: 'regtest',
		wallet: opts.wallet,
		sweepDestinationScript: opts.sweepDestinationScript,
		// Object.create skips the constructor, so the class-field initializer
		// never runs; give the bound a real value (short: tests must be fast).
		_closeAddressLookupTimeoutMs: opts.lookupTimeoutMs ?? 500
	}) as unknown as BeignetNode;
}

describe('closeChannel wallet-credited payout (issue #542)', () => {
	it('pays the next unused CHANGE address when the wallet can produce one, never the receive address (issue #1064)', async () => {
		const capture: ICloseCapture = {};
		const bn = closableNode({
			capture,
			wallet: {
				getNextAvailableAddress: async (): Promise<unknown> => bothChains()
			}
		});
		const result = await bn.closeChannel(CHANNEL_ID);
		expect(result.ok).to.equal(true);
		expect(capture.script?.equals(scriptOf(CHANGE_ADDR))).to.equal(true);
		expect(capture.script?.equals(scriptOf(RECEIVE_ADDR))).to.equal(false);
	});

	it("a receive request's address (the one POST /address/new handed out) is never the close destination", async () => {
		// The bug: the request's address IS the next unused receive address
		// until it is paid, so the old close paid into it and the request
		// read as partly paid.
		const capture: ICloseCapture = {};
		const bn = closableNode({
			capture,
			wallet: {
				getNextAvailableAddress: async (): Promise<unknown> => bothChains()
			}
		});
		const requestAddress = await bn.getNewAddress();
		expect(requestAddress).to.equal(RECEIVE_ADDR);
		await bn.closeChannel(CHANNEL_ID);
		expect(capture.script).to.not.be.undefined;
		expect(capture.script?.equals(scriptOf(requestAddress))).to.equal(false);
	});

	it('a never-settling address lookup cannot park the close (issue #542 review)', async () => {
		// getNextAvailableAddress can enter an Electrum handshake with no
		// timeout of its own. The close must fall through to the cached
		// script at the bound instead of waiting forever.
		const capture: ICloseCapture = {};
		const sweepScript = scriptOf(CHANGE_ADDR);
		const bn = closableNode({
			capture,
			sweepDestinationScript: sweepScript,
			lookupTimeoutMs: 50,
			wallet: {
				getNextAvailableAddress: (): Promise<never> =>
					new Promise<never>(() => {
						/* never settles */
					})
			}
		});
		const result = await bn.closeChannel(CHANNEL_ID);
		expect(result.ok).to.equal(true);
		expect(capture.script?.equals(sweepScript)).to.equal(true);
	});

	it('skips the offline wallet legs: offline with no cached script pays the funding key', async () => {
		// getAddress({index: '0'}) works offline, but on a mature wallet
		// index 0 can sit outside the 20-address scan window and nothing
		// rescues it; the funding key IS rescued (recoverFallbackFunds), so
		// the close chain must prefer it (issue #542 review). The stored
		// change address the force-close startup resolution falls back to
		// since issue #1064 is not a leg of this chain either.
		const capture: ICloseCapture = {};
		const bn = closableNode({
			capture,
			wallet: {
				getNextAvailableAddress: async (): Promise<never> => {
					throw new Error('electrum down');
				},
				getChangeAddress: async (): Promise<unknown> => storedChange(),
				getAddress: async (): Promise<string> => INDEX0_ADDR
			}
		});
		await bn.closeChannel(CHANNEL_ID);
		expect(capture.script?.equals(scriptOf(INDEX0_ADDR))).to.equal(false);
		expect(capture.script?.equals(scriptOf(STORED_CHANGE_ADDR))).to.equal(
			false
		);
		expect(capture.script?.equals(scriptOf(FUNDING_ADDR))).to.equal(true);
	});

	it('falls back to the startup sweep script when the wallet has no address', async () => {
		const capture: ICloseCapture = {};
		const sweepScript = scriptOf(STORED_CHANGE_ADDR);
		const bn = closableNode({
			capture,
			sweepDestinationScript: sweepScript,
			wallet: {
				getNextAvailableAddress: async (): Promise<never> => {
					throw new Error('electrum down');
				},
				getChangeAddress: async (): Promise<unknown> => storedChange(),
				getAddress: async (): Promise<undefined> => undefined
			}
		});
		await bn.closeChannel(CHANNEL_ID);
		expect(capture.script?.equals(sweepScript)).to.equal(true);
	});

	it('terminates in the funding-key script when nothing else resolves', async () => {
		// The final leg preserves the old behavior exactly: a locally derived
		// script we control, rescuable by recoverFallbackFunds.
		const capture: ICloseCapture = {};
		const bn = closableNode({
			capture,
			wallet: {
				getNextAvailableAddress: async (): Promise<never> => {
					throw new Error('electrum down');
				},
				getChangeAddress: async (): Promise<never> => {
					throw new Error('wallet locked');
				},
				getAddress: async (): Promise<never> => {
					throw new Error('wallet locked');
				}
			}
		});
		await bn.closeChannel(CHANNEL_ID);
		expect(capture.script?.equals(scriptOf(FUNDING_ADDR))).to.equal(true);
	});

	it('still forwards the acceptStaleStateRisk acknowledgement', async () => {
		const capture: ICloseCapture = {};
		const bn = closableNode({
			capture,
			wallet: {
				getNextAvailableAddress: async (): Promise<unknown> => bothChains()
			}
		});
		await bn.closeChannel(CHANNEL_ID, true);
		expect(capture.acceptStaleStateRisk).to.equal(true);
	});
});
