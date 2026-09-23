/**
 * Which watchtowers ride the SOCKS5 proxy (issue #963).
 *
 * TowerConnection resolves its proxy through the same table as peer dials
 * (selectOutboundProxy): a LAN or loopback tower is dialed directly even with a
 * proxy set, because Tor refuses private addresses (before this the tower was
 * proxied whenever a proxy was configured and every session to it failed);
 * a public clearnet tower follows the scope; an onion tower always rides the
 * proxy. A TCP server that records any contact stands in for the proxy.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import net from 'net';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { DEFAULT_TOR_PROXY } from '../../src/lightning/transport/peer-manager';
import {
	ITowerConnectionOptions,
	TowerConnection
} from '../../src/lightning/watchtower/tower-connection';

const towerAddress = (
	host: string,
	port: number
): ITowerConnectionOptions['address'] => {
	const pubkey = getPublicKey(crypto.randomBytes(32)).toString('hex');
	return { pubkey, host, port, uri: `${pubkey}@${host}:${port}` };
};

describe('TowerConnection proxy selection', function () {
	this.timeout(5000);

	let proxy: net.Server;
	let proxyPort = 0;
	let proxyContacted = false;

	beforeEach(async function () {
		proxyContacted = false;
		proxy = net.createServer((s) => {
			proxyContacted = true;
			s.destroy();
		});
		await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
		proxyPort = (proxy.address() as net.AddressInfo).port;
	});

	afterEach(async function () {
		await new Promise<void>((resolve) => proxy.close(() => resolve()));
	});

	const connection = (
		opts: Omit<ITowerConnectionOptions, 'localPrivateKey'>
	): TowerConnection =>
		new TowerConnection({ localPrivateKey: crypto.randomBytes(32), ...opts });

	it('dials a LAN tower directly even with a proxy set', async function () {
		// Port 1 is closed, so the direct dial fails fast with ECONNREFUSED.
		// A proxied dial would instead reach the flag server and fail in the
		// SOCKS negotiation, which is what happened before #963.
		const conn = connection({
			address: towerAddress('127.0.0.1', 1),
			connectTimeoutMs: 2000,
			socks5Proxy: { host: '127.0.0.1', port: proxyPort }
		});
		let error: unknown;
		try {
			await conn.connect();
		} catch (err) {
			error = err;
		}
		conn.close();
		expect((error as Error)?.message ?? '').to.include('ECONNREFUSED');
		expect(proxyContacted, 'proxy should not be contacted for a LAN tower').to
			.be.false;
	});

	it('dials a public clearnet tower directly under scope onion', async function () {
		// 203.0.113.1 is TEST-NET-3 (RFC 5737), never routed: the direct dial
		// fails at once or hits the short connect timeout. The proxy sees
		// nothing either way.
		const conn = connection({
			address: towerAddress('203.0.113.1', 9735),
			connectTimeoutMs: 300,
			socks5Proxy: { host: '127.0.0.1', port: proxyPort },
			socks5ProxyScope: 'onion'
		});
		let error: unknown;
		try {
			await conn.connect();
		} catch (err) {
			error = err;
		}
		conn.close();
		expect(error, 'the direct dial cannot succeed').to.be.instanceOf(Error);
		expect(proxyContacted, 'proxy should not be contacted for a public tower')
			.to.be.false;
	});

	it('routes a public clearnet tower through the proxy under scope all', async function () {
		const conn = connection({
			address: towerAddress('203.0.113.1', 9735),
			connectTimeoutMs: 2000,
			socks5Proxy: { host: '127.0.0.1', port: proxyPort },
			socks5ProxyScope: 'all'
		});
		try {
			await conn.connect();
		} catch {
			// The flag server speaks no SOCKS, so negotiation fails; the point
			// is that the dial was aimed at the proxy at all.
		}
		conn.close();
		expect(proxyContacted, 'proxy should be contacted for a public tower').to.be
			.true;
	});

	it('routes an onion tower through the proxy under scope onion', async function () {
		const conn = connection({
			address: towerAddress('abc123.onion', 9735),
			connectTimeoutMs: 2000,
			socks5Proxy: { host: '127.0.0.1', port: proxyPort },
			socks5ProxyScope: 'onion'
		});
		try {
			await conn.connect();
		} catch {
			// As above: the negotiation fails, the contact is what counts.
		}
		conn.close();
		expect(proxyContacted, 'proxy should be contacted for an onion tower').to.be
			.true;
	});

	it('falls back to the default Tor proxy for an onion tower with no proxy set', function () {
		// No dial: the resolved proxy is read off the instance.
		const resolved = (
			conn: TowerConnection
		): { host: string; port: number } | undefined =>
			(conn as unknown as { socks5Proxy?: { host: string; port: number } })
				.socks5Proxy;
		expect(
			resolved(connection({ address: towerAddress('abc123.onion', 9735) }))
		).to.deep.equal(DEFAULT_TOR_PROXY);
		expect(
			resolved(
				connection({
					address: towerAddress('abc123.onion', 9735),
					socks5ProxyScope: 'onion'
				})
			)
		).to.deep.equal(DEFAULT_TOR_PROXY);
		expect(
			resolved(connection({ address: towerAddress('203.0.113.1', 9735) }))
		).to.equal(undefined);
	});
});
