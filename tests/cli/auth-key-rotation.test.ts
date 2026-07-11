/**
 * API key rotation, expiry, and durable auth-key overrides.
 *
 * Follows up the scoped-auth M6 suite (tests/cli/auth-scopes.test.ts):
 * - expiresAt on named keys: validated at construction, enforced at
 *   authenticate() time (an expired key fails exactly like a bad key).
 * - POST /auth/keys/rotate mints a random 32-byte secret, returned once;
 *   the old secret stops authenticating immediately.
 * - Rotation and revocation persist through an AuthOverrideStore (the
 *   daemon backs it with the encrypted wallet_data table) and survive a
 *   daemon restart, fixing the M6 in-memory-revocation limitation. Config
 *   stays the source of truth for the key set: overrides apply by name and
 *   are pruned when the name left the config or its config secret changed.
 *
 * Daemon suites boot offline (unreachable Electrum, same pattern as
 * auth-scopes.test.ts): auth decisions happen before route handlers.
 */

import { expect } from 'chai';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { startDaemon } from '../../src/cli/daemon';
import {
	ApiKeyAuthenticator,
	ApiScope,
	AuthOverrideStore,
	StoredKeyOverride
} from '../../src/cli/auth';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const HEX64 = /^[0-9a-f]{64}$/;

function isoIn(ms: number): string {
	return new Date(Date.now() + ms).toISOString();
}

function sha256Hex(input: string): string {
	return createHash('sha256').update(input, 'utf8').digest('hex');
}

function request(
	port: number,
	method: string,
	urlPath: string,
	token?: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {};
		if (payload) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
		if (token) headers['Authorization'] = `Bearer ${token}`;
		const req = http.request(
			{ hostname: '127.0.0.1', port, path: urlPath, method, headers },
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve({
							status: res.statusCode!,
							body: JSON.parse(Buffer.concat(chunks).toString())
						});
					} catch {
						resolve({ status: res.statusCode!, body: {} });
					}
				});
			}
		);
		req.on('error', reject);
		if (payload) req.write(payload);
		req.end();
	});
}

/** In-memory AuthOverrideStore standing in for the daemon's sqlite wiring. */
class MemoryStore implements AuthOverrideStore {
	data: Record<string, StoredKeyOverride> | null = null;
	saves = 0;

	load(): Record<string, StoredKeyOverride> | null {
		return this.data === null
			? null
			: (JSON.parse(JSON.stringify(this.data)) as Record<
					string,
					StoredKeyOverride
			  >);
	}

	save(overrides: Record<string, StoredKeyOverride>): void {
		this.saves++;
		this.data = JSON.parse(JSON.stringify(overrides)) as Record<
			string,
			StoredKeyOverride
		>;
	}
}

// ─────────────── Expiry (unit) ───────────────

describe('ApiKeyAuthenticator expiry', () => {
	it('accepts ISO 8601 expiresAt; keys without expiry never expire', () => {
		const auth = new ApiKeyAuthenticator(undefined, [
			{
				name: 'temp',
				key: 'temp-secret',
				scopes: ['readonly'],
				expiresAt: isoIn(86_400_000)
			},
			{ name: 'forever', key: 'forever-secret', scopes: ['readonly'] }
		]);
		expect(auth.authenticate('Bearer temp-secret').ok).to.equal(true);
		expect(auth.authenticate('Bearer forever-secret').ok).to.equal(true);
	});

	it('rejects unparseable expiresAt at construction with INVALID_PARAMS', () => {
		for (const bad of [
			'not-a-date',
			'',
			'2027-13-45T99:99:99Z',
			12345 as unknown as string
		]) {
			try {
				new ApiKeyAuthenticator(undefined, [
					{ name: 'a', key: 'k', scopes: ['readonly'], expiresAt: bad }
				]);
				expect.fail(`expected expiresAt=${JSON.stringify(bad)} to throw`);
			} catch (err) {
				expect(err).to.be.instanceOf(BeignetError);
				expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
				expect((err as BeignetError).message).to.include('expiresAt');
			}
		}
	});

	it('an expired key fails authentication exactly like a bad key', () => {
		const auth = new ApiKeyAuthenticator('legacy-token', [
			{
				name: 'stale',
				key: 'stale-secret',
				scopes: ['admin'],
				expiresAt: isoIn(-1000)
			},
			{ name: 'live', key: 'live-secret', scopes: ['readonly'] }
		]);
		expect(auth.authenticate('Bearer stale-secret').ok).to.equal(false);
		// Other credentials unaffected
		expect(auth.authenticate('Bearer live-secret').ok).to.equal(true);
		expect(auth.authenticate('Bearer legacy-token').ok).to.equal(true);
	});

	it('expiry is evaluated at authenticate() time, not at construction', async () => {
		const auth = new ApiKeyAuthenticator(undefined, [
			{
				name: 'shortlived',
				key: 'shortlived-secret',
				scopes: ['readonly'],
				expiresAt: isoIn(150)
			}
		]);
		expect(auth.authenticate('Bearer shortlived-secret').ok).to.equal(true);
		await new Promise((r) => setTimeout(r, 300));
		expect(auth.authenticate('Bearer shortlived-secret').ok).to.equal(false);
		expect(auth.listKeys()[0].expired).to.equal(true);
	});

	it('listKeys reports expiresAt and a computed expired flag', () => {
		const future = isoIn(86_400_000);
		const past = isoIn(-86_400_000);
		const auth = new ApiKeyAuthenticator(undefined, [
			{ name: 'fresh', key: 'k1', scopes: ['readonly'], expiresAt: future },
			{ name: 'stale', key: 'k2', scopes: ['readonly'], expiresAt: past },
			{ name: 'forever', key: 'k3', scopes: ['readonly'] }
		]);
		const listed = auth.listKeys();
		const fresh = listed.find((k) => k.name === 'fresh');
		const stale = listed.find((k) => k.name === 'stale');
		const forever = listed.find((k) => k.name === 'forever');
		expect(fresh).to.deep.include({ expired: false, expiresAt: future });
		expect(stale).to.deep.include({ expired: true, expiresAt: past });
		expect(forever?.expired).to.equal(false);
		expect(forever).to.not.have.property('expiresAt');
	});
});

// ─────────────── Rotation (unit) ───────────────

describe('ApiKeyAuthenticator rotation', () => {
	const keys = (): Array<{
		name: string;
		key: string;
		scopes: ApiScope[];
	}> => [
		{ name: 'monitor', key: 'ro-secret', scopes: ['readonly'] },
		{ name: 'shop', key: 'inv-secret', scopes: ['invoice'] }
	];

	it('rotate mints a 32-byte hex secret; old dies, new works, scopes kept', () => {
		const auth = new ApiKeyAuthenticator('legacy-token', keys());
		const rotated = auth.rotate('shop');
		expect(rotated).to.not.equal(null);
		expect(rotated!.name).to.equal('shop');
		expect(rotated!.key).to.match(HEX64);
		expect(Number.isFinite(Date.parse(rotated!.rotatedAt))).to.equal(true);

		expect(auth.authenticate('Bearer inv-secret').ok).to.equal(false);
		const result = auth.authenticate(`Bearer ${rotated!.key}`);
		expect(result.ok).to.equal(true);
		if (result.ok) {
			expect(result.keyName).to.equal('shop');
			expect([...result.scopes]).to.deep.equal(['invoice']);
		}
		// Other credentials unaffected
		expect(auth.authenticate('Bearer ro-secret').ok).to.equal(true);
		expect(auth.authenticate('Bearer legacy-token').ok).to.equal(true);
	});

	it('successive rotations each produce a distinct secret', () => {
		const auth = new ApiKeyAuthenticator(undefined, keys());
		const first = auth.rotate('shop')!;
		const second = auth.rotate('shop')!;
		expect(first.key).to.not.equal(second.key);
		expect(auth.authenticate(`Bearer ${first.key}`).ok).to.equal(false);
		expect(auth.authenticate(`Bearer ${second.key}`).ok).to.equal(true);
	});

	it('returns null for unknown names and the nameless legacy token', () => {
		const auth = new ApiKeyAuthenticator('legacy-token', keys());
		expect(auth.rotate('nope')).to.equal(null);
		expect(auth.rotate('legacy-token')).to.equal(null);
		// Legacy token keeps working unchanged
		expect(auth.authenticate('Bearer legacy-token').ok).to.equal(true);
	});

	it('rotating a revoked key reinstates it under the new secret only', () => {
		const auth = new ApiKeyAuthenticator(undefined, keys());
		expect(auth.revoke('shop')).to.equal(true);
		expect(auth.authenticate('Bearer inv-secret').ok).to.equal(false);
		const rotated = auth.rotate('shop')!;
		expect(auth.listKeys().find((k) => k.name === 'shop')?.revoked).to.equal(
			false
		);
		expect(auth.authenticate(`Bearer ${rotated.key}`).ok).to.equal(true);
		// The pre-revocation secret stays dead
		expect(auth.authenticate('Bearer inv-secret').ok).to.equal(false);
	});

	it('listKeys reports rotatedAt after rotation, never the secret', () => {
		const auth = new ApiKeyAuthenticator(undefined, keys());
		const rotated = auth.rotate('monitor')!;
		const entry = auth.listKeys().find((k) => k.name === 'monitor');
		expect(entry?.rotatedAt).to.equal(rotated.rotatedAt);
		expect(JSON.stringify(auth.listKeys())).to.not.include(rotated.key);
	});
});

// ─────────────── Override store (unit) ───────────────

describe('ApiKeyAuthenticator override store', () => {
	const keys = (): Array<{
		name: string;
		key: string;
		scopes: ApiScope[];
	}> => [
		{ name: 'monitor', key: 'ro-secret', scopes: ['readonly'] },
		{ name: 'shop', key: 'inv-secret', scopes: ['invoice'] }
	];

	it('revocation persists across a reconstruction (restart simulation)', () => {
		const store = new MemoryStore();
		const auth = new ApiKeyAuthenticator(undefined, keys());
		auth.attachOverrideStore(store);
		auth.revoke('monitor');

		const restarted = new ApiKeyAuthenticator(undefined, keys());
		restarted.attachOverrideStore(store);
		expect(restarted.authenticate('Bearer ro-secret').ok).to.equal(false);
		expect(
			restarted.listKeys().find((k) => k.name === 'monitor')?.revoked
		).to.equal(true);
		expect(restarted.authenticate('Bearer inv-secret').ok).to.equal(true);
	});

	it('rotation persists: old secret dead, new secret live after restart', () => {
		const store = new MemoryStore();
		const auth = new ApiKeyAuthenticator(undefined, keys());
		auth.attachOverrideStore(store);
		const rotated = auth.rotate('shop')!;
		// Only the digest is persisted, never the plaintext secret
		expect(JSON.stringify(store.data)).to.not.include(rotated.key);
		expect(store.data?.shop.keyDigest).to.equal(sha256Hex(rotated.key));

		const restarted = new ApiKeyAuthenticator(undefined, keys());
		restarted.attachOverrideStore(store);
		expect(restarted.authenticate('Bearer inv-secret').ok).to.equal(false);
		const result = restarted.authenticate(`Bearer ${rotated.key}`);
		expect(result.ok).to.equal(true);
		if (result.ok) expect([...result.scopes]).to.deep.equal(['invoice']);
		expect(
			restarted.listKeys().find((k) => k.name === 'shop')?.rotatedAt
		).to.equal(rotated.rotatedAt);
	});

	it('prunes overrides whose name is no longer in the config', () => {
		const store = new MemoryStore();
		store.data = {
			ghost: { configDigest: sha256Hex('gone'), revoked: true }
		};
		const auth = new ApiKeyAuthenticator(undefined, keys());
		auth.attachOverrideStore(store);
		expect(store.data).to.deep.equal({});
		expect(auth.authenticate('Bearer ro-secret').ok).to.equal(true);
	});

	it('a config re-key discards the stored override (config wins)', () => {
		const store = new MemoryStore();
		const auth = new ApiKeyAuthenticator(undefined, keys());
		auth.attachOverrideStore(store);
		auth.revoke('monitor');
		auth.rotate('shop');

		// Operator changes both secrets in the config file and restarts
		const rekeyed = new ApiKeyAuthenticator(undefined, [
			{ name: 'monitor', key: 'new-ro-secret', scopes: ['readonly'] },
			{ name: 'shop', key: 'new-inv-secret', scopes: ['invoice'] }
		]);
		rekeyed.attachOverrideStore(store);
		expect(rekeyed.authenticate('Bearer new-ro-secret').ok).to.equal(true);
		expect(rekeyed.authenticate('Bearer new-inv-secret').ok).to.equal(true);
		expect(
			rekeyed.listKeys().find((k) => k.name === 'monitor')?.revoked
		).to.equal(false);
		expect(store.data).to.deep.equal({});
	});

	it('prunes malformed entries and applies valid ones', () => {
		const store = new MemoryStore();
		store.data = {
			monitor: {
				configDigest: sha256Hex('ro-secret'),
				revoked: true
			},
			shop: {
				configDigest: sha256Hex('inv-secret'),
				keyDigest: 'zz-not-hex'
			} as StoredKeyOverride
		};
		const auth = new ApiKeyAuthenticator(undefined, keys());
		auth.attachOverrideStore(store);
		// monitor override applied, malformed shop override pruned
		expect(auth.authenticate('Bearer ro-secret').ok).to.equal(false);
		expect(auth.authenticate('Bearer inv-secret').ok).to.equal(true);
		expect(store.data).to.deep.equal({
			monitor: { configDigest: sha256Hex('ro-secret'), revoked: true }
		});
	});

	it('a stored expiresAt override applies over the config value', () => {
		const store = new MemoryStore();
		store.data = {
			monitor: {
				configDigest: sha256Hex('ro-secret'),
				expiresAt: isoIn(-1000)
			}
		};
		const auth = new ApiKeyAuthenticator(undefined, keys());
		auth.attachOverrideStore(store);
		expect(auth.authenticate('Bearer ro-secret').ok).to.equal(false);
		const entry = auth.listKeys().find((k) => k.name === 'monitor');
		expect(entry?.expired).to.equal(true);
		expect(entry?.expiresAt).to.be.a('string');
	});

	it('rotate and revoke still work without a store (process lifetime)', () => {
		const auth = new ApiKeyAuthenticator(undefined, keys());
		expect(auth.revoke('monitor')).to.equal(true);
		expect(auth.authenticate('Bearer ro-secret').ok).to.equal(false);
		const rotated = auth.rotate('shop')!;
		expect(auth.authenticate(`Bearer ${rotated.key}`).ok).to.equal(true);
	});
});

// ─────────────── Daemon enforcement (offline integration) ───────────────

describe('Daemon API key rotation and expiry', function () {
	this.timeout(120_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	const LEGACY = 'legacy-admin-token';
	const RO_KEY = 'readonly-key-secret';
	const INV_KEY = 'invoice-key-secret';
	const STALE_KEY = 'stale-key-secret';
	const FRESH_KEY = 'fresh-key-secret';
	const PAST = isoIn(-86_400_000);
	const FUTURE = isoIn(86_400_000);

	before(async function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-auth-rotation-'));
		({ server, node } = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			daemonPort: 0,
			apiToken: LEGACY,
			apiKeys: [
				{ name: 'monitor', key: RO_KEY, scopes: ['readonly'] },
				{ name: 'shop', key: INV_KEY, scopes: ['invoice'] },
				{
					name: 'stale',
					key: STALE_KEY,
					scopes: ['readonly'],
					expiresAt: PAST
				},
				{
					name: 'fresh',
					key: FRESH_KEY,
					scopes: ['readonly'],
					expiresAt: FUTURE
				}
			]
		}));
		port = (server.address() as AddressInfo).port;
	});

	after(async function () {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('an expired key gets 401; a future-expiry key works', async () => {
		const expired = await request(port, 'GET', '/info', STALE_KEY);
		expect(expired.status).to.equal(401);
		expect((expired.body.error as { code: string }).code).to.equal(
			'UNAUTHORIZED'
		);
		const fresh = await request(port, 'GET', '/info', FRESH_KEY);
		expect(fresh.status).to.equal(200);
		const noExpiry = await request(port, 'GET', '/info', RO_KEY);
		expect(noExpiry.status).to.equal(200);
	});

	it('GET /auth/keys reports expiry fields and never secrets', async () => {
		const keys = await request(port, 'GET', '/auth/keys', LEGACY);
		expect(keys.status).to.equal(200);
		const listed = (
			keys.body.result as { keys: Array<Record<string, unknown>> }
		).keys;
		const stale = listed.find((k) => k.name === 'stale');
		const fresh = listed.find((k) => k.name === 'fresh');
		const monitor = listed.find((k) => k.name === 'monitor');
		expect(stale?.expired).to.equal(true);
		expect(stale?.expiresAt).to.equal(PAST);
		expect(fresh?.expired).to.equal(false);
		expect(fresh?.expiresAt).to.equal(FUTURE);
		expect(monitor?.expired).to.equal(false);
		expect(monitor).to.not.have.property('expiresAt');
		const raw = JSON.stringify(keys.body);
		for (const secret of [RO_KEY, INV_KEY, STALE_KEY, FRESH_KEY, LEGACY]) {
			expect(raw).to.not.include(secret);
		}
	});

	it('rotate is admin-only and validates its input', async () => {
		const denied = await request(port, 'POST', '/auth/keys/rotate', RO_KEY, {
			name: 'shop'
		});
		expect(denied.status).to.equal(403);
		expect((denied.body.error as { code: string }).code).to.equal('FORBIDDEN');

		const missing = await request(
			port,
			'POST',
			'/auth/keys/rotate',
			LEGACY,
			{}
		);
		expect((missing.body.error as { code: string }).code).to.equal(
			'INVALID_PARAMS'
		);

		const unknown = await request(port, 'POST', '/auth/keys/rotate', LEGACY, {
			name: 'never-existed'
		});
		expect((unknown.body.error as { code: string }).code).to.equal('NOT_FOUND');

		// The legacy token has no name and cannot be rotated
		const legacy = await request(port, 'POST', '/auth/keys/rotate', LEGACY, {
			name: LEGACY
		});
		expect((legacy.body.error as { code: string }).code).to.equal('NOT_FOUND');
		expect((legacy.body.error as { message: string }).message).to.include(
			'apiToken'
		);
	});

	it('rotate returns the new secret once; old dies, scopes preserved', async () => {
		const before = await request(port, 'POST', '/invoice/create', INV_KEY, {
			amountSats: 100
		});
		expect(before.status).to.equal(200);

		const rotate = await request(port, 'POST', '/auth/keys/rotate', LEGACY, {
			name: 'shop'
		});
		expect(rotate.status).to.equal(200);
		const result = rotate.body.result as {
			name: string;
			key: string;
			rotatedAt: string;
			warning: string;
		};
		expect(result.name).to.equal('shop');
		expect(result.key).to.match(HEX64);
		expect(result.warning).to.include('once');

		// Old secret dead immediately
		const old = await request(port, 'POST', '/invoice/create', INV_KEY, {
			amountSats: 100
		});
		expect(old.status).to.equal(401);

		// New secret works with the same scopes: invoice yes, node state no
		const create = await request(port, 'POST', '/invoice/create', result.key, {
			amountSats: 100
		});
		expect(create.status).to.equal(200);
		const info = await request(port, 'GET', '/info', result.key);
		expect(info.status).to.equal(403);

		// The list shows rotatedAt but never the new secret
		const keys = await request(port, 'GET', '/auth/keys', LEGACY);
		const shop = (
			keys.body.result as { keys: Array<Record<string, unknown>> }
		).keys.find((k) => k.name === 'shop');
		expect(shop?.rotatedAt).to.equal(result.rotatedAt);
		expect(JSON.stringify(keys.body)).to.not.include(result.key);
	});
});

// ─────────────── Restart durability (offline integration) ───────────────

describe('Auth key overrides survive a daemon restart', function () {
	this.timeout(180_000);

	let tmpDir: string;
	let server: http.Server | undefined;
	let node: BeignetNode | undefined;

	const LEGACY = 'legacy-admin-token';
	const RO_KEY = 'readonly-key-secret';
	const INV_KEY = 'invoice-key-secret';

	const daemonOpts = (): Parameters<typeof startDaemon>[0] => ({
		mnemonic: MNEMONIC,
		network: 'regtest',
		dataDir: tmpDir,
		logLevel: 'silent',
		rapidGossipSync: false,
		autoGossipSync: false,
		electrumHost: '127.0.0.1',
		electrumPort: 65529,
		electrumTls: false,
		daemonPort: 0,
		apiToken: LEGACY,
		apiKeys: [
			{ name: 'monitor', key: RO_KEY, scopes: ['readonly'] },
			{ name: 'shop', key: INV_KEY, scopes: ['invoice'] }
		]
	});

	before(function () {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-auth-restart-'));
	});

	after(async function () {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('revocation and rotation persist across restart with the same config', async function () {
		// First daemon: revoke monitor, rotate shop
		({ server, node } = await startDaemon(daemonOpts()));
		let port = (server.address() as AddressInfo).port;

		expect((await request(port, 'GET', '/info', RO_KEY)).status).to.equal(200);
		const revoke = await request(port, 'POST', '/auth/keys/revoke', LEGACY, {
			name: 'monitor'
		});
		expect(revoke.status).to.equal(200);
		const rotate = await request(port, 'POST', '/auth/keys/rotate', LEGACY, {
			name: 'shop'
		});
		const newShopKey = (rotate.body.result as { key: string }).key;
		expect(newShopKey).to.match(HEX64);

		// Stop the first daemon (releases the data-dir lock)
		server.close();
		await node.destroy();
		server = undefined;
		node = undefined;

		// Second daemon: SAME config file contents, SAME data dir
		({ server, node } = await startDaemon(daemonOpts()));
		port = (server.address() as AddressInfo).port;

		// Revocation survived: the config-declared secret stays dead
		const revokedStill = await request(port, 'GET', '/info', RO_KEY);
		expect(revokedStill.status).to.equal(401);

		// Rotation survived: old secret dead, rotated secret works with scopes
		expect(
			(
				await request(port, 'POST', '/invoice/create', INV_KEY, {
					amountSats: 100
				})
			).status
		).to.equal(401);
		const create = await request(port, 'POST', '/invoice/create', newShopKey, {
			amountSats: 100
		});
		expect(create.status).to.equal(200);
		expect((await request(port, 'GET', '/info', newShopKey)).status).to.equal(
			403
		);

		// Legacy token untouched by all of this
		expect((await request(port, 'GET', '/info', LEGACY)).status).to.equal(200);

		// The listing reflects the persisted state
		const keys = await request(port, 'GET', '/auth/keys', LEGACY);
		const listed = (
			keys.body.result as { keys: Array<Record<string, unknown>> }
		).keys;
		expect(listed.find((k) => k.name === 'monitor')?.revoked).to.equal(true);
		expect(listed.find((k) => k.name === 'shop')?.rotatedAt).to.be.a('string');
		expect(JSON.stringify(keys.body)).to.not.include(newShopKey);

		// Rotating again on the restarted daemon chains cleanly
		const again = await request(port, 'POST', '/auth/keys/rotate', LEGACY, {
			name: 'shop'
		});
		const newerShopKey = (again.body.result as { key: string }).key;
		expect(
			(await request(port, 'GET', '/invoices', newShopKey)).status
		).to.equal(401);
		expect(
			(await request(port, 'GET', '/invoices', newerShopKey)).status
		).to.equal(200);
	});

	it('startDaemon rejects an unparseable expiresAt before booting a node', async function () {
		try {
			await startDaemon({
				mnemonic: MNEMONIC,
				network: 'regtest',
				dataDir: tmpDir,
				daemonPort: 0,
				apiKeys: [
					{
						name: 'bad',
						key: 'k',
						scopes: ['readonly'],
						expiresAt: 'tomorrow-ish'
					}
				]
			});
			expect.fail('expected startDaemon to throw');
		} catch (err) {
			expect(err).to.be.instanceOf(BeignetError);
			expect((err as BeignetError).code).to.equal('INVALID_PARAMS');
			expect((err as BeignetError).message).to.include('expiresAt');
		}
	});
});
