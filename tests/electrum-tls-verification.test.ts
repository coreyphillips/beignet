/**
 * Issue #1046: rn-electrum-client dials TLS with rejectUnauthorized: false, so
 * the plain `tls` module accepts any certificate. withTlsVerification wraps the
 * injected module so the same client refuses a certificate that neither chains
 * to a trusted CA for the host nor matches a pinned fingerprint.
 *
 * Offline: every connection goes to a local TLS server with a throwaway
 * self-signed certificate, through the library's own client.
 */

import { expect } from 'chai';
import { execSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import tls from 'tls';

import { Tls, withTlsVerification } from '../src';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const Client = require('rn-electrum-client/lib/client');

const connectThrough = async (
	tlsModule: Tls,
	host: string,
	port: number
): Promise<{ error: boolean; pong?: unknown }> => {
	const client = new Client(port, host, 'tls', net, tlsModule);
	const res = await client.connect();
	if (res.error) {
		return { error: true };
	}
	const pong = await client.request('server.ping', []);
	client.close();
	return { error: false, pong };
};

describe('Electrum TLS verification (#1046)', () => {
	let dir: string;
	let cert: string;
	let fingerprint: string;
	let server: tls.Server;
	let port: number;

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-tls-'));
		const keyPath = path.join(dir, 'key.pem');
		const certPath = path.join(dir, 'cert.pem');
		const { privateKey } = crypto.generateKeyPairSync('rsa', {
			modulusLength: 2048,
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
			publicKeyEncoding: { type: 'spki', format: 'pem' }
		});
		fs.writeFileSync(keyPath, privateKey);
		execSync(
			`openssl req -new -x509 -key ${keyPath} -out ${certPath} -days 1 -subj "/CN=localhost" -batch 2>/dev/null`
		);
		cert = fs.readFileSync(certPath, 'utf8');
		fingerprint = new crypto.X509Certificate(cert).fingerprint256;

		server = tls.createServer({ key: privateKey, cert }, (socket) => {
			socket.setEncoding('utf8');
			socket.on('data', (chunk: string) => {
				for (const line of chunk.split('\n').filter(Boolean)) {
					const { id } = JSON.parse(line);
					socket.write(
						JSON.stringify({ jsonrpc: '2.0', id, result: 'pong' }) + '\n'
					);
				}
			});
			socket.on('error', () => undefined);
		});
		await new Promise<void>((resolve) =>
			server.listen(0, '127.0.0.1', resolve)
		);
		port = (server.address() as net.AddressInfo).port;
	});

	after(() => {
		server.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('the plain tls module accepts a self-signed certificate', async () => {
		const res = await connectThrough(tls, '127.0.0.1', port);
		expect(res).to.deep.equal({ error: false, pong: 'pong' });
	});

	it('refuses a self-signed certificate that is not pinned', async () => {
		const res = await connectThrough(
			withTlsVerification(tls),
			'127.0.0.1',
			port
		);
		expect(res.error).to.equal(true);
	});

	it('accepts a pinned certificate, in either fingerprint spelling', async () => {
		const colons = await connectThrough(
			withTlsVerification(tls, { fingerprints: [fingerprint] }),
			'127.0.0.1',
			port
		);
		expect(colons).to.deep.equal({ error: false, pong: 'pong' });

		const bare = await connectThrough(
			withTlsVerification(tls, {
				fingerprints: [fingerprint.replace(/:/g, '').toLowerCase()]
			}),
			'127.0.0.1',
			port
		);
		expect(bare).to.deep.equal({ error: false, pong: 'pong' });
	});

	it('refuses a certificate whose fingerprint is not the pinned one', async () => {
		const res = await connectThrough(
			withTlsVerification(tls, { fingerprints: ['AB'.repeat(32)] }),
			'127.0.0.1',
			port
		);
		expect(res.error).to.equal(true);
	});

	it('accepts a CA-verified certificate only for the host it names', async () => {
		// Stands in for the system CA store: the certificate is its own CA.
		// family 4 keeps "localhost" on the loopback address the server holds
		// (a net option the tls typings leave out).
		const trusting = {
			...tls,
			connect: (options: tls.ConnectionOptions, listener?: () => void) => {
				const withCa = { ...options, ca: cert, family: 4 };
				return tls.connect(withCa, listener);
			}
		} as Tls;
		const named = await connectThrough(
			withTlsVerification(trusting),
			'localhost',
			port
		);
		expect(named).to.deep.equal({ error: false, pong: 'pong' });

		const mismatched = await connectThrough(
			withTlsVerification(trusting),
			'127.0.0.1',
			port
		);
		expect(mismatched.error).to.equal(true);
	});

	it('rejects a malformed fingerprint up front', () => {
		expect(() =>
			withTlsVerification(tls, { fingerprints: ['not-hex'] })
		).to.throw(/Invalid SHA-256 fingerprint/);
	});
});
