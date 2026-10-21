/**
 * Electrum TLS certificate verification for the daemon (issue #1776):
 * BEIGNET_ELECTRUM_TLS_VERIFY and BEIGNET_ELECTRUM_TLS_FINGERPRINTS resolution,
 * startup validation, and what the node actually dials with.
 *
 * Offline: config resolution needs no node, the refusals use an unreachable
 * Electrum, and the boot cases dial a local TLS server with a throwaway
 * self-signed certificate that records each connection and then hangs up.
 */

import { expect } from 'chai';
import { execSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import * as tls from 'tls';
import { BeignetNode } from '../../src/cli/beignet-node';
import { resolveConfig, saveConfig } from '../../src/cli/config';
import { startDaemon } from '../../src/cli/daemon';
import { daemonOptions } from '../../src/cli/daemon-options';
import {
	checkElectrumTls,
	claimElectrumTls,
	releaseElectrumTls
} from '../../src/cli/electrum-tls-config';
import { BeignetError } from '../../src/cli/errors';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const PIN = 'AB'.repeat(32);

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	daemonPort: 0
};

describe('resolveConfig electrumTlsVerify and electrumTlsFingerprints', () => {
	const origHome = process.env.HOME;
	let tmpHome: string;

	beforeEach(() => {
		// The config file lives under $HOME/.beignet, so a fresh HOME starts
		// from no file at all and the file-key case writes there.
		tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tls-verify-'));
		process.env.HOME = tmpHome;
	});

	afterEach(() => {
		process.env.HOME = origHome;
		delete process.env.BEIGNET_ELECTRUM_TLS_VERIFY;
		delete process.env.BEIGNET_ELECTRUM_TLS_FINGERPRINTS;
		fs.rmSync(tmpHome, { recursive: true, force: true });
	});

	it('leaves both unset when nothing sets them, so verification stays off', () => {
		const resolved = resolveConfig({});
		expect(resolved.electrumTlsVerify).to.equal(undefined);
		expect(resolved.electrumTlsFingerprints).to.equal(undefined);
	});

	it('reads BEIGNET_ELECTRUM_TLS_VERIFY=true and =false', () => {
		process.env.BEIGNET_ELECTRUM_TLS_VERIFY = 'true';
		expect(resolveConfig({}).electrumTlsVerify).to.equal(true);
		process.env.BEIGNET_ELECTRUM_TLS_VERIFY = 'false';
		expect(resolveConfig({}).electrumTlsVerify).to.equal(false);
	});

	it('treats an empty BEIGNET_ELECTRUM_TLS_VERIFY as unset', () => {
		process.env.BEIGNET_ELECTRUM_TLS_VERIFY = '';
		expect(resolveConfig({}).electrumTlsVerify).to.equal(undefined);
	});

	it('refuses anything else, so a typo cannot leave verification off', () => {
		for (const junk of ['TRUE', '1', 'yes', 'on']) {
			process.env.BEIGNET_ELECTRUM_TLS_VERIFY = junk;
			expect(() => resolveConfig({}), junk).to.throw(
				/BEIGNET_ELECTRUM_TLS_VERIFY must be exactly true or false/
			);
		}
	});

	it('splits BEIGNET_ELECTRUM_TLS_FINGERPRINTS on commas and drops blanks', () => {
		process.env.BEIGNET_ELECTRUM_TLS_FINGERPRINTS = ` ${PIN} ,, cd:ef `;
		expect(resolveConfig({}).electrumTlsFingerprints).to.deep.equal([
			PIN,
			'cd:ef'
		]);
		process.env.BEIGNET_ELECTRUM_TLS_FINGERPRINTS = ' , ';
		expect(resolveConfig({}).electrumTlsFingerprints).to.equal(undefined);
	});

	it('reads the config file keys, below the env vars', () => {
		saveConfig({ electrumTlsVerify: true, electrumTlsFingerprints: [PIN] });
		expect(resolveConfig({}).electrumTlsVerify).to.equal(true);
		expect(resolveConfig({}).electrumTlsFingerprints).to.deep.equal([PIN]);

		process.env.BEIGNET_ELECTRUM_TLS_VERIFY = 'false';
		process.env.BEIGNET_ELECTRUM_TLS_FINGERPRINTS = 'cd'.repeat(32);
		expect(resolveConfig({}).electrumTlsVerify).to.equal(false);
		expect(resolveConfig({}).electrumTlsFingerprints).to.deep.equal([
			'cd'.repeat(32)
		]);
	});

	it('hands both to the daemon options', () => {
		process.env.BEIGNET_ELECTRUM_TLS_VERIFY = 'true';
		process.env.BEIGNET_ELECTRUM_TLS_FINGERPRINTS = PIN;
		const opts = daemonOptions(resolveConfig({}), 2112);
		expect(opts.electrumTlsVerify).to.equal(true);
		expect(opts.electrumTlsFingerprints).to.deep.equal([PIN]);
	});
});

describe('claimElectrumTls', () => {
	// Network names no real node uses, so a node another test file left
	// running in this worker cannot hold a claim on them.
	const NET = 'claim-test-net';
	const OTHER_NET = 'claim-test-other-net';
	const VERIFY = { electrumTlsVerify: true };
	const PINNED = { electrumTlsVerify: true, electrumTlsFingerprints: [PIN] };
	const DIFFERENT = /different electrumTlsVerify or electrumTlsFingerprints/;
	const a = {};
	const b = {};

	afterEach(() => {
		releaseElectrumTls(a);
		releaseElectrumTls(b);
	});

	it('refuses a second holder with another setting on the same network', () => {
		claimElectrumTls(a, NET, {});
		expect(() => claimElectrumTls(b, NET, VERIFY)).to.throw(DIFFERENT);
		expect(() => checkElectrumTls(NET, PINNED)).to.throw(DIFFERENT);
		releaseElectrumTls(a);

		claimElectrumTls(a, NET, PINNED);
		expect(() => claimElectrumTls(b, NET, VERIFY)).to.throw(DIFFERENT);
		expect(() => claimElectrumTls(b, NET, {})).to.throw(DIFFERENT);
	});

	it('accepts the same setting, however the pins are written', () => {
		claimElectrumTls(a, NET, { electrumTlsVerify: false });
		claimElectrumTls(b, NET, {});
		releaseElectrumTls(a);
		releaseElectrumTls(b);

		const other = 'cd'.repeat(32);
		claimElectrumTls(a, NET, {
			electrumTlsVerify: true,
			electrumTlsFingerprints: [PIN, other]
		});
		claimElectrumTls(b, NET, {
			electrumTlsVerify: true,
			electrumTlsFingerprints: [
				other.toUpperCase(),
				PIN.match(/../g)!.join(':'),
				PIN
			]
		});
	});

	it('keeps networks apart', () => {
		claimElectrumTls(a, NET, {});
		claimElectrumTls(b, OTHER_NET, PINNED);
	});

	it('lets a holder claim again, and frees the network once it releases', () => {
		claimElectrumTls(a, NET, {});
		claimElectrumTls(a, NET, PINNED);
		expect(() => claimElectrumTls(b, NET, {})).to.throw(DIFFERENT);
		releaseElectrumTls(a);
		releaseElectrumTls(a);
		claimElectrumTls(b, NET, {});
	});
});

describe('electrumTlsVerify at startup', function () {
	this.timeout(60_000);

	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tls-verify-boot-'));
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	const refused = async (
		opts: Record<string, unknown>,
		pattern: RegExp
	): Promise<void> => {
		let error: unknown;
		try {
			const daemon = await startDaemon({
				...OFFLINE,
				mnemonic: MNEMONIC,
				dataDir: dir,
				...opts
			});
			await daemon.stop();
		} catch (e) {
			error = e;
		}
		expect(error, 'expected startDaemon to refuse').to.be.instanceOf(
			BeignetError
		);
		expect((error as Error).message).to.match(pattern);
	};

	it('refuses pinned fingerprints without electrumTlsVerify', async () => {
		// Ignoring them would leave the operator believing the pinned server
		// is checked when no certificate is.
		await refused(
			{ electrumTlsFingerprints: [PIN] },
			/needs electrumTlsVerify: true/
		);
	});

	it('refuses a malformed fingerprint with the wrapper error', async () => {
		await refused(
			{ electrumTlsVerify: true, electrumTlsFingerprints: ['not-hex'] },
			/Invalid SHA-256 fingerprint: NOT-HEX/
		);
	});

	it('refuses an electrumTlsVerify that is not a boolean', async () => {
		await refused(
			{ electrumTlsVerify: 'yes' },
			/electrumTlsVerify must be a boolean/
		);
	});

	it('warns, rather than refuses, when the configured server is plain TCP', async () => {
		// Verification still covers the TLS fallback servers, so this is not
		// an error, but the pin is never used for the configured server.
		const warnings: string[] = [];
		const ignore = (): void => undefined;
		const node = await BeignetNode.create({
			...OFFLINE,
			mnemonic: MNEMONIC,
			dataDir: dir,
			electrumTlsVerify: true,
			electrumTlsFingerprints: [PIN],
			logLevel: 'warn',
			logger: {
				debug: ignore,
				info: ignore,
				warn: (message: string) => warnings.push(message),
				error: ignore
			}
		});
		await node.destroy();
		expect(
			warnings.some((w) =>
				/configured Electrum server is plain TCP, so its certificate is never checked/.test(
					w
				)
			),
			warnings.join('\n')
		).to.equal(true);
	});

	describe('against a self-signed Electrum server', () => {
		let certDir: string;
		let key: string;
		let cert: string;
		let fingerprint: string;
		let server: tls.Server;
		let port: number;
		/** TCP connections the node opened, whatever became of them. */
		let dials: number;
		/** One entry per handshake the server completed: the SNI it carried, and
		 *  whether the client went on to send a request. A client that refuses
		 *  the certificate hangs up before the server's side of a TLS 1.3
		 *  handshake finishes, so it may leave no entry at all. */
		let seen: Array<{ servername: string | false; requested: boolean }>;

		before(() => {
			certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tls-cert-'));
			const keyPath = path.join(certDir, 'key.pem');
			const certPath = path.join(certDir, 'cert.pem');
			key = crypto
				.generateKeyPairSync('rsa', {
					modulusLength: 2048,
					privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
					publicKeyEncoding: { type: 'spki', format: 'pem' }
				})
				.privateKey.toString();
			fs.writeFileSync(keyPath, key);
			execSync(
				`openssl req -new -x509 -key ${keyPath} -out ${certPath} -days 1 -subj "/CN=localhost" -batch 2>/dev/null`
			);
			cert = fs.readFileSync(certPath, 'utf8');
			fingerprint = new crypto.X509Certificate(cert).fingerprint256;
		});

		after(() => {
			fs.rmSync(certDir, { recursive: true, force: true });
		});

		beforeEach(async () => {
			dials = 0;
			seen = [];
			server = tls.createServer({ key, cert }, (socket) => {
				const entry = {
					servername: (socket as tls.TLSSocket & { servername: string | false })
						.servername,
					requested: false
				};
				seen.push(entry);
				// Record the first request and hang up: the client fails its
				// connect the same way an unreachable server does, so the node
				// boots without Electrum and the test only reads what it sent.
				socket.once('data', () => {
					entry.requested = true;
					socket.destroy();
				});
				socket.on('error', () => undefined);
			});
			server.on('connection', () => {
				dials++;
			});
			server.on('tlsClientError', () => undefined);
			await new Promise<void>((resolve) =>
				server.listen(0, '127.0.0.1', resolve)
			);
			port = (server.address() as net.AddressInfo).port;
		});

		afterEach(async () => {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		});

		const create = (
			opts: Record<string, unknown>,
			dataDir = dir
		): Promise<BeignetNode> =>
			// "localhost" so the daemon pins it to 127.0.0.1 before dialing,
			// which is the case the configured name has to survive.
			BeignetNode.create({
				...OFFLINE,
				mnemonic: MNEMONIC,
				dataDir,
				electrumHost: 'localhost',
				electrumPort: port,
				electrumTls: true,
				...opts
			});

		/** Waits for a dial past `before`, then for the request that follows. */
		const settle = async (before: number): Promise<void> => {
			const deadline = Date.now() + 10_000;
			while (dials === before && Date.now() < deadline) {
				await new Promise((resolve) => setTimeout(resolve, 50));
			}
			// A request, when one comes, follows the handshake at once.
			await new Promise((resolve) => setTimeout(resolve, 200));
		};

		const boot = async (
			opts: Record<string, unknown>,
			dataDir = dir
		): Promise<void> => {
			const before = dials;
			const node = await create(opts, dataDir);
			try {
				await settle(before);
			} finally {
				await node.destroy();
			}
		};

		const requests = (): number => seen.filter((s) => s.requested).length;

		it('accepts the certificate unchecked when verification is off (the default)', async () => {
			await boot({});
			expect(seen.some((s) => s.requested)).to.equal(true);
		});

		it('refuses the certificate when verification is on and it is not pinned', async () => {
			await boot({ electrumTlsVerify: true });
			expect(dials, 'dials').to.be.greaterThan(0);
			expect(seen.some((s) => s.requested)).to.equal(false);
		});

		it('accepts a pinned certificate and sends the configured name after the IPv4 pin', async () => {
			await boot({
				electrumTlsVerify: true,
				electrumTlsFingerprints: [fingerprint]
			});
			expect(seen.some((s) => s.requested)).to.equal(true);
			// Without the mapping the dial goes to 127.0.0.1 with no SNI at
			// all, and a CA-issued certificate for the name would never match.
			expect(seen.map((s) => s.servername)).to.include('localhost');
		});

		it('refuses a node whose setting differs from a running node on the network, in either order', async () => {
			// rn-electrum-client shares one client per network across the
			// process, so the second node would otherwise send its requests
			// over the first one's socket without checking it (or, the other
			// way round, have it swapped for an unchecked one).
			const otherDir = fs.mkdtempSync(
				path.join(os.tmpdir(), 'beignet-tls-verify-boot-')
			);
			const pinned = {
				electrumTlsVerify: true,
				electrumTlsFingerprints: [fingerprint]
			};
			try {
				for (const [first, second] of [
					[{}, pinned],
					[pinned, {}]
				]) {
					const before = dials;
					const running = await create(first);
					try {
						await settle(before);
						let error: unknown;
						try {
							await (await create(second, otherDir)).destroy();
						} catch (e) {
							error = e;
						}
						expect(
							error,
							'expected the second node to be refused'
						).to.be.instanceOf(BeignetError);
						expect((error as BeignetError).code).to.equal('INVALID_PARAMS');
						expect((error as Error).message).to.match(
							/different electrumTlsVerify or electrumTlsFingerprints/
						);
					} finally {
						await running.destroy();
					}
					// The refusal held nothing: once the first node is gone the
					// same data directory boots with the other setting.
					const sent = requests();
					await boot(second, otherDir);
					expect(requests()).to.be.greaterThan(sent);
				}
			} finally {
				fs.rmSync(otherDir, { recursive: true, force: true });
			}
		});
	});
});
