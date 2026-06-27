/**
 * Force-close sweep destination resolution.
 *
 * A remote force-close detected at startup gets its to_local/to_remote swept to
 * `getSweepDestinationScript()`. When the wallet sweep address is undefined that
 * resolves to the funding-key P2WPKH fallback — an address the on-chain wallet
 * does NOT scan, leaving recovered sats confirmed but invisible until a later
 * recoverFallbackFunds pass.
 *
 * resolveWalletSweepScript() must therefore ALWAYS yield a wallet-owned address:
 * the preferred unused-address lookup needs Electrum, but it must fall back to
 * deterministic (network-free) derivation so a force-close detected while
 * Electrum is still connecting never pins the sweep to the invisible fallback.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetNode } from '../../src/cli/beignet-node';

const NETWORK = bitcoin.networks.bitcoin;
// BIP173 mainnet P2WPKH test vector — a stand-in "next unused" wallet address.
const UNUSED_ADDR = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
// A real wallet-owned P2WPKH (the index-0 derivation stand-in).
const DERIVED_ADDR = 'bc1qa4kyhz5j36mynpvj75hg6ms4nrq58h60n2ghv0';

function callResolve(wallet: any): Promise<Buffer | undefined> {
	const fakeThis = { wallet, getBitcoinNetwork: () => NETWORK };
	return (BeignetNode.prototype as any).resolveWalletSweepScript.call(fakeThis);
}

const okResult = (address: string): any => ({
	isOk: () => true,
	isErr: () => false,
	value: { addressIndex: { address } }
});
const errResult = (): any => ({
	isOk: () => false,
	isErr: () => true,
	error: { message: 'electrum not connected' }
});

describe('Force-close sweep destination resolution', () => {
	it('uses the next unused wallet address when Electrum is available', async () => {
		const wallet = {
			getNextAvailableAddress: async () => okResult(UNUSED_ADDR),
			getAddress: async () => {
				throw new Error(
					'getAddress should not be reached when the unused lookup succeeds'
				);
			}
		};
		const script = await callResolve(wallet);
		expect(script).to.deep.equal(
			bitcoin.address.toOutputScript(UNUSED_ADDR, NETWORK)
		);
	});

	it('falls back to deterministic wallet derivation when the unused lookup fails (Electrum down)', async () => {
		let derivedIndex: string | undefined;
		const wallet = {
			getNextAvailableAddress: async () => errResult(),
			getAddress: async (opts: { index?: string }) => {
				derivedIndex = opts.index;
				return DERIVED_ADDR;
			}
		};
		const script = await callResolve(wallet);
		// The whole point: a wallet-owned script is still returned, so the sweep
		// never targets the invisible funding-key fallback.
		expect(script).to.deep.equal(
			bitcoin.address.toOutputScript(DERIVED_ADDR, NETWORK)
		);
		expect(derivedIndex).to.equal('0');
	});

	it('falls back to derivation when the unused lookup throws', async () => {
		const wallet = {
			getNextAvailableAddress: async () => {
				throw new Error('electrum timeout');
			},
			getAddress: async () => DERIVED_ADDR
		};
		const script = await callResolve(wallet);
		expect(script).to.deep.equal(
			bitcoin.address.toOutputScript(DERIVED_ADDR, NETWORK)
		);
	});

	it('returns undefined only when both the unused lookup AND derivation fail', async () => {
		const wallet = {
			getNextAvailableAddress: async () => errResult(),
			getAddress: async () => '' // wallet could not derive an address
		};
		const script = await callResolve(wallet);
		expect(script).to.be.undefined;
	});
});
