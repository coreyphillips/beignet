/**
 * BEIGNET_AUTO_RECONNECT resolution — offline tests.
 *
 * autoReconnect existed on the library API from the start (BeignetNode
 * defaults it true) but the daemon never plumbed it, so a daemon-run node
 * always dialed its peers back. Turning it off, together with omitting the
 * listen port, is what lets an operator deliberately park a Lightning node:
 * channels stay watched on-chain but unreachable over the wire.
 */

import { expect } from 'chai';
import { resolveConfig } from '../../src/cli/config';

describe('resolveConfig autoReconnect', () => {
	afterEach(() => {
		delete process.env.BEIGNET_AUTO_RECONNECT;
	});

	it('is undefined when nothing sets it, so the node default (true) rules', () => {
		const resolved = resolveConfig({});
		expect(resolved.autoReconnect).to.equal(undefined);
	});

	it('resolves false from BEIGNET_AUTO_RECONNECT=false', () => {
		process.env.BEIGNET_AUTO_RECONNECT = 'false';
		const resolved = resolveConfig({});
		expect(resolved.autoReconnect).to.equal(false);
	});

	it('resolves true from BEIGNET_AUTO_RECONNECT=true', () => {
		process.env.BEIGNET_AUTO_RECONNECT = 'true';
		const resolved = resolveConfig({});
		expect(resolved.autoReconnect).to.equal(true);
	});

	it('ignores anything but exact true/false, so a typo cannot park a node', () => {
		// Ignored falls back to the node default, reconnect ON: the safe
		// direction, since a silently parked node's unreachable channels are
		// eventually force-closed by the reestablish watchdog.
		for (const junk of ['TRUE', 'FALSE', '1', '0', 'yes', '']) {
			process.env.BEIGNET_AUTO_RECONNECT = junk;
			const resolved = resolveConfig({});
			expect(resolved.autoReconnect, JSON.stringify(junk)).to.equal(undefined);
		}
	});

	it('prefers the CLI flag over the env var', () => {
		process.env.BEIGNET_AUTO_RECONNECT = 'true';
		const resolved = resolveConfig({ autoReconnect: false });
		expect(resolved.autoReconnect).to.equal(false);
	});
});
