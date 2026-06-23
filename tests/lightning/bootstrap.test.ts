/**
 * BOLT 10: DNS Bootstrap Tests.
 *
 * Tests for DNS-based peer discovery including:
 * - IPeerAddress type validation
 * - SRV record parsing
 * - extractPubkeyFromHostname
 * - DNS seed resolution (with mocked DNS)
 * - resolveARecords / resolveSrvRecords
 * - Default DNS seed configuration
 * - Bootstrap peer aggregation
 * - Barrel export verification
 */

import { expect } from 'chai';
import sinon from 'sinon';
import dns from 'dns';
import crypto from 'crypto';
import {
	IPeerAddress,
	IDnsSeedConfig,
	IBootstrapConfig
} from '../../src/lightning/bootstrap/types';
import {
	parseSrvRecord,
	resolveARecords,
	resolveSrvRecords,
	resolveDnsSeed,
	extractPubkeyFromHostname
} from '../../src/lightning/bootstrap/dns';
import {
	DEFAULT_DNS_SEEDS,
	bootstrapPeers
} from '../../src/lightning/bootstrap/seeds';
import * as bootstrap from '../../src/lightning/bootstrap';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// ─────────────── Helpers ───────────────

/** Generate a valid compressed pubkey hex string. */
function makeValidPubkeyHex(): string {
	const privkey = crypto.randomBytes(32);
	return getPublicKey(privkey).toString('hex');
}

describe('Lightning Bootstrap (BOLT 10)', function () {
	let sandbox: sinon.SinonSandbox;

	beforeEach(function () {
		sandbox = sinon.createSandbox();
	});

	afterEach(function () {
		sandbox.restore();
	});

	// ─── IPeerAddress type ──────────────────────────────────────

	describe('IPeerAddress type', function () {
		it('should accept a valid peer address structure', function () {
			const addr: IPeerAddress = {
				pubkey: crypto.randomBytes(33),
				host: '127.0.0.1',
				port: 9735
			};
			expect(addr.pubkey).to.be.instanceOf(Buffer);
			expect(addr.host).to.equal('127.0.0.1');
			expect(addr.port).to.equal(9735);
		});

		it('should store pubkey as a 33-byte buffer', function () {
			const pubkey = crypto.randomBytes(33);
			const addr: IPeerAddress = {
				pubkey,
				host: '10.0.0.1',
				port: 9735
			};
			expect(addr.pubkey.length).to.equal(33);
			expect(addr.pubkey).to.deep.equal(pubkey);
		});

		it('should accept any valid port number', function () {
			const addr1: IPeerAddress = {
				pubkey: Buffer.alloc(33),
				host: 'a',
				port: 1
			};
			const addr2: IPeerAddress = {
				pubkey: Buffer.alloc(33),
				host: 'a',
				port: 65535
			};
			const addr3: IPeerAddress = {
				pubkey: Buffer.alloc(33),
				host: 'a',
				port: 9735
			};
			expect(addr1.port).to.equal(1);
			expect(addr2.port).to.equal(65535);
			expect(addr3.port).to.equal(9735);
		});
	});

	// ─── parseSrvRecord ──────────────────────────────────────

	describe('parseSrvRecord', function () {
		it('should parse a valid SRV record', function () {
			const result = parseSrvRecord({
				name: 'node1.lightning.directory',
				port: 9735,
				priority: 10,
				weight: 5
			});
			expect(result.host).to.equal('node1.lightning.directory');
			expect(result.port).to.equal(9735);
		});

		it('should extract host and port correctly', function () {
			const result = parseSrvRecord({
				name: 'example.com',
				port: 19735,
				priority: 0,
				weight: 0
			});
			expect(result.host).to.equal('example.com');
			expect(result.port).to.equal(19735);
		});

		it('should handle different hostnames', function () {
			const result = parseSrvRecord({
				name: 'sub.domain.example.org',
				port: 443,
				priority: 1,
				weight: 10
			});
			expect(result.host).to.equal('sub.domain.example.org');
			expect(result.port).to.equal(443);
		});

		it('should strip trailing dots from FQDN hostnames', function () {
			const result = parseSrvRecord({
				name: 'node1.lightning.directory.',
				port: 9735,
				priority: 10,
				weight: 5
			});
			expect(result.host).to.equal('node1.lightning.directory');
		});

		it('should handle records with zero port', function () {
			const result = parseSrvRecord({
				name: 'host.example.com',
				port: 0,
				priority: 0,
				weight: 0
			});
			expect(result.host).to.equal('host.example.com');
			expect(result.port).to.equal(0);
		});
	});

	// ─── extractPubkeyFromHostname ──────────────────────────────────────

	describe('extractPubkeyFromHostname', function () {
		it('should extract a valid hex pubkey from hostname labels', function () {
			const pubkeyHex = makeValidPubkeyHex();
			const hostname = `${pubkeyHex}.nodes.lightning.directory`;
			const result = extractPubkeyFromHostname(hostname);
			expect(result.toString('hex')).to.equal(pubkeyHex);
			expect(result.length).to.equal(33);
		});

		it('should return zero buffer when no pubkey found', function () {
			const result = extractPubkeyFromHostname('some.random.hostname.com');
			expect(result.length).to.equal(33);
			expect(result).to.deep.equal(Buffer.alloc(33));
		});

		it('should handle hostname with trailing dot', function () {
			const pubkeyHex = makeValidPubkeyHex();
			const hostname = `${pubkeyHex}.nodes.lightning.directory.`;
			const result = extractPubkeyFromHostname(hostname);
			expect(result.toString('hex')).to.equal(pubkeyHex);
		});

		it('should reject hex labels that do not start with 02 or 03', function () {
			// 66-char hex but starts with 04 -- not a valid compressed pubkey prefix
			const fakeHex = '04' + 'a'.repeat(64);
			const hostname = `${fakeHex}.example.com`;
			const result = extractPubkeyFromHostname(hostname);
			expect(result).to.deep.equal(Buffer.alloc(33));
		});

		it('should find pubkey in any label position', function () {
			const pubkeyHex = makeValidPubkeyHex();
			const hostname = `prefix.${pubkeyHex}.suffix.com`;
			const result = extractPubkeyFromHostname(hostname);
			expect(result.toString('hex')).to.equal(pubkeyHex);
		});
	});

	// ─── resolveARecords ──────────────────────────────────────

	describe('resolveARecords', function () {
		it('should resolve A records via dns.resolve4', async function () {
			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['93.184.216.34']);
				});

			const addresses = await resolveARecords('example.com');
			expect(addresses).to.deep.equal(['93.184.216.34']);
		});

		it('should resolve multiple A records', async function () {
			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['1.2.3.4', '5.6.7.8']);
				});

			const addresses = await resolveARecords('multi.example.com');
			expect(addresses.length).to.equal(2);
			expect(addresses).to.include('1.2.3.4');
			expect(addresses).to.include('5.6.7.8');
		});

		it('should reject on DNS error', async function () {
			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(new Error('ENOTFOUND'), null);
				});

			try {
				await resolveARecords('nonexistent.example');
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.equal('ENOTFOUND');
			}
		});
	});

	// ─── resolveSrvRecords ──────────────────────────────────────

	describe('resolveSrvRecords', function () {
		it('should resolve SRV records via dns.resolveSrv', async function () {
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{ name: 'node1.example.com', port: 9735, priority: 10, weight: 5 }
					]);
				});

			const records = await resolveSrvRecords('_lightning._tcp.example.com');
			expect(records.length).to.equal(1);
			expect(records[0].name).to.equal('node1.example.com');
			expect(records[0].port).to.equal(9735);
		});

		it('should reject on DNS error', async function () {
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(new Error('ESERVFAIL'), null);
				});

			try {
				await resolveSrvRecords('_lightning._tcp.bad.example');
				expect.fail('Should have thrown');
			} catch (err) {
				expect((err as Error).message).to.equal('ESERVFAIL');
			}
		});
	});

	// ─── resolveDnsSeed (mocked DNS) ──────────────────────────────────────

	describe('resolveDnsSeed', function () {
		it('should return peer addresses from SRV + A records', async function () {
			const pubkeyHex = makeValidPubkeyHex();

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{
							name: `${pubkeyHex}.nodes.lightning.directory`,
							port: 9735,
							priority: 10,
							weight: 5
						}
					]);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['1.2.3.4']);
				});

			const seed: IDnsSeedConfig = { hostname: 'nodes.lightning.directory' };
			const peers = await resolveDnsSeed(seed, 5000);

			expect(peers.length).to.equal(1);
			expect(peers[0].pubkey.toString('hex')).to.equal(pubkeyHex);
			expect(peers[0].host).to.equal('1.2.3.4');
			expect(peers[0].port).to.equal(9735);
		});

		it('should return empty array on SRV lookup failure', async function () {
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(new Error('ENOTFOUND'), null);
				});

			const seed: IDnsSeedConfig = { hostname: 'nonexistent.seed.example' };
			const peers = await resolveDnsSeed(seed, 5000);

			expect(peers).to.deep.equal([]);
		});

		it('should skip SRV records whose A resolution fails', async function () {
			const pubkey1 = makeValidPubkeyHex();
			const pubkey2 = makeValidPubkeyHex();

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{
							name: `${pubkey1}.seed.example`,
							port: 9735,
							priority: 10,
							weight: 5
						},
						{
							name: `${pubkey2}.seed.example`,
							port: 9735,
							priority: 10,
							weight: 5
						}
					]);
				});

			let callCount = 0;
			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callCount++;
					if (callCount === 1) {
						callback(new Error('ENOTFOUND'), null);
					} else {
						callback(null, ['5.6.7.8']);
					}
				});

			const seed: IDnsSeedConfig = { hostname: 'seed.example' };
			const peers = await resolveDnsSeed(seed, 5000);

			// Only the second SRV record's A lookup succeeded
			expect(peers.length).to.equal(1);
			expect(peers[0].host).to.equal('5.6.7.8');
		});

		it('should reject with timeout on slow DNS', async function () {
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, _callback: Function) => {
					// Never call callback -- simulate hanging DNS
				});

			const seed: IDnsSeedConfig = { hostname: 'slow.seed.example' };
			try {
				await resolveDnsSeed(seed, 50); // 50ms timeout
				expect.fail('Should have thrown timeout error');
			} catch (err) {
				expect((err as Error).message).to.equal('DNS resolution timeout');
			}
		});

		it('should return empty array when SRV returns no records', async function () {
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, []);
				});

			const seed: IDnsSeedConfig = { hostname: 'empty.seed.example' };
			const peers = await resolveDnsSeed(seed, 5000);

			expect(peers).to.deep.equal([]);
		});

		it('should use default port 9735 when SRV port is 0', async function () {
			const pubkeyHex = makeValidPubkeyHex();

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{
							name: `${pubkeyHex}.seed.example`,
							port: 0,
							priority: 10,
							weight: 5
						}
					]);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['10.0.0.1']);
				});

			const seed: IDnsSeedConfig = { hostname: 'seed.example' };
			const peers = await resolveDnsSeed(seed, 5000);

			expect(peers.length).to.equal(1);
			expect(peers[0].port).to.equal(9735);
		});

		it('should handle multiple SRV records', async function () {
			const pubkey1 = makeValidPubkeyHex();
			const pubkey2 = makeValidPubkeyHex();
			const pubkey3 = makeValidPubkeyHex();

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{
							name: `${pubkey1}.seed.example`,
							port: 9735,
							priority: 10,
							weight: 5
						},
						{
							name: `${pubkey2}.seed.example`,
							port: 9736,
							priority: 20,
							weight: 3
						},
						{
							name: `${pubkey3}.seed.example`,
							port: 9737,
							priority: 30,
							weight: 1
						}
					]);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((hostname: string, callback: Function) => {
					if (hostname.includes(pubkey1)) {
						callback(null, ['1.1.1.1']);
					} else if (hostname.includes(pubkey2)) {
						callback(null, ['2.2.2.2']);
					} else {
						callback(null, ['3.3.3.3']);
					}
				});

			const seed: IDnsSeedConfig = { hostname: 'seed.example' };
			const peers = await resolveDnsSeed(seed, 5000);

			expect(peers.length).to.equal(3);
			const hosts = peers.map((p) => p.host).sort();
			expect(hosts).to.deep.equal(['1.1.1.1', '2.2.2.2', '3.3.3.3']);
		});

		it('should use custom defaultPort from seed config', async function () {
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{ name: 'node.example.com', port: 0, priority: 10, weight: 5 }
					]);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['10.0.0.1']);
				});

			const seed: IDnsSeedConfig = {
				hostname: 'seed.example',
				defaultPort: 19735
			};
			const peers = await resolveDnsSeed(seed, 5000);

			expect(peers.length).to.equal(1);
			expect(peers[0].port).to.equal(19735);
		});

		it('should query SRV on the bare seed domain (BOLT 10)', async function () {
			let queriedDomain = '';
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((hostname: string, callback: Function) => {
					queriedDomain = hostname;
					callback(null, []);
				});

			const seed: IDnsSeedConfig = { hostname: 'nodes.lightning.directory' };
			await resolveDnsSeed(seed, 5000);

			// BOLT 10 seeds are queried on the bare domain, not under _lightning._tcp.
			expect(queriedDomain).to.equal('nodes.lightning.directory');
		});

		it('should decode a bech32 (ln1...) node id from an SRV target', function () {
			// ln1 + bech32 of a 33-byte compressed pubkey (0x02...) → 33-byte buffer.
			const { bech32 } = require('bech32');
			const pubkey = Buffer.concat([
				Buffer.from([0x02]),
				Buffer.alloc(32, 0x11)
			]);
			const label = bech32.encode('ln', bech32.toWords(pubkey), 256);
			const result = extractPubkeyFromHostname(
				`${label}.nodes.lightning.directory`
			);
			expect(result.equals(pubkey)).to.equal(true);
		});
	});

	// ─── DEFAULT_DNS_SEEDS ──────────────────────────────────────

	describe('DEFAULT_DNS_SEEDS', function () {
		it('should have expected number of seeds', function () {
			expect(DEFAULT_DNS_SEEDS.length).to.equal(3);
		});

		it('should have hostname on all seeds', function () {
			for (const seed of DEFAULT_DNS_SEEDS) {
				expect(seed.hostname).to.be.a('string');
				expect(seed.hostname.length).to.be.greaterThan(0);
			}
		});

		it('should include nodes.lightning.directory', function () {
			const hostnames = DEFAULT_DNS_SEEDS.map((s) => s.hostname);
			expect(hostnames).to.include('nodes.lightning.directory');
		});
	});

	// ─── bootstrapPeers ──────────────────────────────────────

	describe('bootstrapPeers', function () {
		it('should return deduplicated peers from seeds', async function () {
			const pubkey1 = makeValidPubkeyHex();
			const pubkey2 = makeValidPubkeyHex();

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{
							name: `${pubkey1}.seed.example`,
							port: 9735,
							priority: 10,
							weight: 5
						},
						{
							name: `${pubkey2}.seed.example`,
							port: 9735,
							priority: 20,
							weight: 3
						}
					]);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((hostname: string, callback: Function) => {
					if (hostname.includes(pubkey1)) {
						callback(null, ['1.1.1.1']);
					} else {
						callback(null, ['2.2.2.2']);
					}
				});

			const config: IBootstrapConfig = {
				seeds: [{ hostname: 'seed.example' }],
				maxPeers: 25,
				timeoutMs: 5000
			};
			const peers = await bootstrapPeers(config);

			expect(peers.length).to.equal(2);
			const pubkeys = peers.map((p) => p.pubkey.toString('hex')).sort();
			expect(pubkeys).to.include(pubkey1);
			expect(pubkeys).to.include(pubkey2);
		});

		it('should respect maxPeers limit', async function () {
			const pubkeys = Array.from({ length: 10 }, () => makeValidPubkeyHex());

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(
						null,
						pubkeys.map((pk, i) => ({
							name: `${pk}.seed.example`,
							port: 9735,
							priority: i,
							weight: 1
						}))
					);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['10.0.0.1']);
				});

			const config: IBootstrapConfig = {
				seeds: [{ hostname: 'seed.example' }],
				maxPeers: 3,
				timeoutMs: 5000
			};
			const peers = await bootstrapPeers(config);

			expect(peers.length).to.equal(3);
		});

		it('should use default seeds when none provided', async function () {
			// Stub DNS to fail for all seeds -- just check it doesn't throw
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(new Error('ENOTFOUND'), null);
				});

			const peers = await bootstrapPeers({ timeoutMs: 100 });
			expect(peers).to.be.an('array');
		});

		it('should handle all seeds failing gracefully', async function () {
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(new Error('ENOTFOUND'), null);
				});

			const config: IBootstrapConfig = {
				seeds: [{ hostname: 'fail1.example' }, { hostname: 'fail2.example' }],
				timeoutMs: 100
			};
			const peers = await bootstrapPeers(config);

			expect(peers).to.deep.equal([]);
		});

		it('should handle partial seed failures', async function () {
			const pubkey = makeValidPubkeyHex();

			let callNum = 0;
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callNum++;
					if (callNum === 1) {
						callback(new Error('ENOTFOUND'), null);
					} else {
						callback(null, [
							{
								name: `${pubkey}.seed.example`,
								port: 9735,
								priority: 10,
								weight: 5
							}
						]);
					}
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['8.8.8.8']);
				});

			const config: IBootstrapConfig = {
				seeds: [{ hostname: 'fail.example' }, { hostname: 'good.example' }],
				timeoutMs: 5000
			};
			const peers = await bootstrapPeers(config);

			expect(peers.length).to.equal(1);
			expect(peers[0].pubkey.toString('hex')).to.equal(pubkey);
		});

		it('should deduplicate peers by pubkey across seeds', async function () {
			const pubkey = makeValidPubkeyHex();

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{
							name: `${pubkey}.seed.example`,
							port: 9735,
							priority: 10,
							weight: 5
						}
					]);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['1.2.3.4']);
				});

			const config: IBootstrapConfig = {
				seeds: [{ hostname: 'seed1.example' }, { hostname: 'seed2.example' }],
				maxPeers: 25,
				timeoutMs: 5000
			};
			const peers = await bootstrapPeers(config);

			// Same pubkey from both seeds -- deduplicated to 1
			expect(peers.length).to.equal(1);
			expect(peers[0].pubkey.toString('hex')).to.equal(pubkey);
		});

		it('should return empty array on total failure', async function () {
			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(new Error('ENOTFOUND'), null);
				});

			const config: IBootstrapConfig = {
				seeds: [{ hostname: 'dead.example' }],
				timeoutMs: 100
			};
			const peers = await bootstrapPeers(config);

			expect(peers).to.be.an('array');
			expect(peers.length).to.equal(0);
		});

		it('should use custom seeds', async function () {
			const pubkey = makeValidPubkeyHex();

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{
							name: `${pubkey}.my-seed.example`,
							port: 19735,
							priority: 10,
							weight: 5
						}
					]);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['192.168.1.1']);
				});

			const config: IBootstrapConfig = {
				seeds: [{ hostname: 'my-seed.example' }]
			};
			const peers = await bootstrapPeers(config);

			expect(peers.length).to.equal(1);
			expect(peers[0].host).to.equal('192.168.1.1');
			expect(peers[0].port).to.equal(19735);
		});

		it('should handle multiple A records per SRV target', async function () {
			const pubkey = makeValidPubkeyHex();

			sandbox
				.stub(dns, 'resolveSrv')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, [
						{
							name: `${pubkey}.seed.example`,
							port: 9735,
							priority: 10,
							weight: 5
						}
					]);
				});

			sandbox
				.stub(dns, 'resolve4')
				.callsFake((_hostname: string, callback: Function) => {
					callback(null, ['1.1.1.1', '2.2.2.2']);
				});

			const config: IBootstrapConfig = {
				seeds: [{ hostname: 'seed.example' }],
				maxPeers: 25,
				timeoutMs: 5000
			};
			const peers = await bootstrapPeers(config);

			// Two A records for the same SRV target, same pubkey -- only first is kept by dedup
			// Both have same pubkey buffer bytes, so dedup keeps 1
			expect(peers.length).to.equal(1);
		});
	});

	// ─── Barrel export ──────────────────────────────────────

	describe('barrel export', function () {
		it('should export all public APIs from bootstrap index', function () {
			expect(typeof bootstrap.bootstrapPeers).to.equal('function');
			expect(typeof bootstrap.resolveDnsSeed).to.equal('function');
			expect(typeof bootstrap.parseSrvRecord).to.equal('function');
			expect(typeof bootstrap.extractPubkeyFromHostname).to.equal('function');
			expect(typeof bootstrap.resolveARecords).to.equal('function');
			expect(typeof bootstrap.resolveSrvRecords).to.equal('function');
			expect(Array.isArray(bootstrap.DEFAULT_DNS_SEEDS)).to.be.true;
		});

		it('should export type interfaces (via runtime existence of defaults)', function () {
			// IBootstrapConfig used in bootstrapPeers config parameter
			// IDnsSeedConfig used in DEFAULT_DNS_SEEDS elements
			// IPeerAddress is the return type -- verified structurally in other tests
			expect(bootstrap.DEFAULT_DNS_SEEDS[0]).to.have.property('hostname');
		});
	});
});
