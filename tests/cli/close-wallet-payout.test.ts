/**
 * Cooperative-close payout destination (issue #542, LFBW port #532
 * workstream 1C).
 *
 * closeChannel pays the mutual-close output to an address the on-chain
 * wallet actually scans: the current unused wallet address first (a BOUNDED
 * lookup, because it can enter an Electrum handshake with no timeout of its
 * own and the close must reach the engine regardless), then the sweep script
 * resolved at startup, and only then the funding-key P2WPKH the old behavior
 * always paid, which recoverFallbackFunds can still rescue. The index-0 leg
 * the force-close startup resolution uses is deliberately NOT in this chain:
 * on a mature wallet index 0 can sit outside the 20-address scan window and
 * nothing rescues it (issue #542 review). Every leg is derived locally from
 * our own keys, so the chain always terminates in a script we control.
 *
 * Engine-stub harness (the funding-refusal-statuses idiom): the captured
 * scriptPubkey handed to the library close IS the observable.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetNode } from '../../src/cli/beignet-node';

const CHANNEL_ID = 'cd'.repeat(32);
const FRESH_ADDR = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';
const INDEX0_ADDR =
	'bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry';
const FUNDING_ADDR = bitcoin.payments.p2wpkh({
	hash: Buffer.alloc(20, 7),
	network: bitcoin.networks.regtest
}).address!;

const scriptOf = (addr: string): Buffer =>
	bitcoin.address.toOutputScript(addr, bitcoin.networks.regtest);

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
	it('pays a fresh wallet address when the wallet can produce one', async () => {
		const capture: ICloseCapture = {};
		const bn = closableNode({
			capture,
			wallet: {
				getNextAvailableAddress: async (): Promise<unknown> => ({
					isOk: (): boolean => true,
					value: { addressIndex: { address: FRESH_ADDR } }
				})
			}
		});
		const result = await bn.closeChannel(CHANNEL_ID);
		expect(result.ok).to.equal(true);
		expect(capture.script?.equals(scriptOf(FRESH_ADDR))).to.equal(true);
	});

	it('a never-settling address lookup cannot park the close (issue #542 review)', async () => {
		// getNextAvailableAddress can enter an Electrum handshake with no
		// timeout of its own. The close must fall through to the cached
		// script at the bound instead of waiting forever.
		const capture: ICloseCapture = {};
		const sweepScript = scriptOf(FRESH_ADDR);
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

	it('skips the index-0 leg: offline with no cached script pays the funding key', async () => {
		// getAddress({index: '0'}) works offline, but on a mature wallet
		// index 0 can sit outside the 20-address scan window and nothing
		// rescues it; the funding key IS rescued (recoverFallbackFunds), so
		// the close chain must prefer it (issue #542 review).
		const capture: ICloseCapture = {};
		const bn = closableNode({
			capture,
			wallet: {
				getNextAvailableAddress: async (): Promise<never> => {
					throw new Error('electrum down');
				},
				getAddress: async (): Promise<string> => INDEX0_ADDR
			}
		});
		await bn.closeChannel(CHANNEL_ID);
		expect(capture.script?.equals(scriptOf(INDEX0_ADDR))).to.equal(false);
		expect(capture.script?.equals(scriptOf(FUNDING_ADDR))).to.equal(true);
	});

	it('falls back to the startup sweep script when the wallet has no address', async () => {
		const capture: ICloseCapture = {};
		const sweepScript = scriptOf(FRESH_ADDR);
		const bn = closableNode({
			capture,
			sweepDestinationScript: sweepScript,
			wallet: {
				getNextAvailableAddress: async (): Promise<never> => {
					throw new Error('electrum down');
				},
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
				getNextAvailableAddress: async (): Promise<unknown> => ({
					isOk: (): boolean => true,
					value: { addressIndex: { address: FRESH_ADDR } }
				})
			}
		});
		await bn.closeChannel(CHANNEL_ID, true);
		expect(capture.acceptStaleStateRisk).to.equal(true);
	});
});
