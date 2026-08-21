/**
 * BEIGNET_EAGER_GOSSIP_VERIFY resolution — offline tests.
 *
 * eagerGossipVerify opts a relay-class node into verifying foreign gossip at
 * intake (issue #443). Wallets keep the lazy default: entries are admitted
 * with deferred provenance and verified only when a gossip query asks for
 * them, and nothing unverified is ever served in either mode.
 */

import { expect } from 'chai';
import { resolveConfig } from '../../src/cli/config';

describe('resolveConfig eagerGossipVerify', () => {
	afterEach(() => {
		delete process.env.BEIGNET_EAGER_GOSSIP_VERIFY;
	});

	it('is undefined when nothing sets it, so the node default (lazy) rules', () => {
		const resolved = resolveConfig({});
		expect(resolved.eagerGossipVerify).to.equal(undefined);
	});

	it('resolves true from BEIGNET_EAGER_GOSSIP_VERIFY=true', () => {
		process.env.BEIGNET_EAGER_GOSSIP_VERIFY = 'true';
		const resolved = resolveConfig({});
		expect(resolved.eagerGossipVerify).to.equal(true);
	});

	it('resolves false from BEIGNET_EAGER_GOSSIP_VERIFY=false', () => {
		process.env.BEIGNET_EAGER_GOSSIP_VERIFY = 'false';
		const resolved = resolveConfig({});
		expect(resolved.eagerGossipVerify).to.equal(false);
	});

	it('ignores anything but exact true/false', () => {
		// Ignored falls back to the node default, lazy verification: the safe
		// direction, since the node still never serves anything unverified, it
		// just verifies later and cheaper.
		for (const junk of ['TRUE', 'FALSE', '1', '0', 'yes', '']) {
			process.env.BEIGNET_EAGER_GOSSIP_VERIFY = junk;
			const resolved = resolveConfig({});
			expect(resolved.eagerGossipVerify, JSON.stringify(junk)).to.equal(
				undefined
			);
		}
	});

	it('prefers the CLI flag over the env var', () => {
		process.env.BEIGNET_EAGER_GOSSIP_VERIFY = 'false';
		const resolved = resolveConfig({ eagerGossipVerify: true });
		expect(resolved.eagerGossipVerify).to.equal(true);
	});
});
