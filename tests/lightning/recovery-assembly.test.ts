/**
 * Guardian recovery assembly (docs/RECOVERY-PROTOCOL.md section 8): the one
 * call embedders share instead of re-deriving the barrier/gate/replicator
 * wiring. Under test:
 *
 * 1. parseGuardianUri accepts exactly the pubkey@url shape and refuses
 *    everything else with a precise message (a silently dropped guardian
 *    would change the quorum arithmetic).
 * 2. A fresh namespace registers and yields a runnable assembly whose gate
 *    confirms against the quorum.
 * 3. A respawn holds its persisted lease WITHOUT touching the network, so a
 *    normal restart never depends on guardian reachability.
 * 4. A fresh database whose namespace the guardians hold is told to restore,
 *    never to register a second genesis; the driver the decision builds
 *    round-trips the state onto the empty target, after which the SAME
 *    assembly call answers run.
 * 5. No quorum means no decision: the assembly refuses rather than guesses.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	CRASH_V1_PROFILE,
	GuardianHttpServer,
	RecoveryCriticality,
	RecoveryManager,
	ReferenceGuardian,
	buildGuardianRecovery,
	guardianDescriptorFor,
	nodeGuardianTransport,
	parseGuardianEntry,
	parseGuardianUri,
	xOnlyFromSecret
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha = (s: string): Buffer =>
	crypto.createHash('sha256').update(s).digest();

const GUARDIAN_SECRETS = [1, 2, 3].map((i) => sha(`assembly-guardian-${i}`));
const GUARDIAN_IDS = GUARDIAN_SECRETS.map((s) => xOnlyFromSecret(s));

let now = 2_230_000_000_000n;
const clock = (): bigint => ++now;

interface IServed {
	guardian: ReferenceGuardian;
	server: GuardianHttpServer;
	url: string;
	id: Buffer;
}

async function serve(index: number): Promise<IServed> {
	const guardian = new ReferenceGuardian({
		path: ':memory:',
		guardianSecret: GUARDIAN_SECRETS[index],
		members: GUARDIAN_IDS,
		clock
	});
	const server = new GuardianHttpServer({ guardian });
	const port = await server.listen(0);
	return {
		guardian,
		server,
		url: `http://127.0.0.1:${port}`,
		id: GUARDIAN_IDS[index]
	};
}

async function shutdown(served: IServed[]): Promise<void> {
	for (const entry of served) {
		try {
			await entry.server.close();
			entry.guardian.close();
		} catch {
			// Already closed by the test.
		}
	}
}

function parsedGuardians(
	served: IServed[]
): Array<{ guardianId: Buffer; url: string }> {
	return served.map((entry) =>
		parseGuardianUri(`${entry.id.toString('hex')}@${entry.url}`)
	);
}

const NODE_SEED = sha('assembly-node-seed');
const NODE_SECRET = crypto
	.createHash('sha256')
	.update(NODE_SEED)
	.update(Buffer.from('node-identity'))
	.digest();

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function createNode(
	storage: SqliteStorage,
	recovery: INodeConfig['recovery']
): LightningNode {
	const node = new LightningNode({
		nodePrivateKey: NODE_SECRET,
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(NODE_SEED),
		perCommitmentSeed: sha('assembly-pcs'),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(NODE_SEED)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(NODE_SEED)
			.update(Buffer.from([4]))
			.digest(),
		storage,
		recovery
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

async function waitFor(
	predicate: () => boolean,
	timeoutMs = 10_000
): Promise<void> {
	const start = Date.now();
	while (!predicate()) {
		if (Date.now() - start > timeoutMs) {
			throw new Error('waitFor timed out');
		}
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

const VALID_ID = GUARDIAN_IDS[0].toString('hex');

describe('Recovery assembly: parseGuardianUri', () => {
	it('accepts pubkey@url with http, https, onion-shaped and loopback hosts', () => {
		for (const url of [
			'https://guardian.example.com',
			'https://guardian.example.com:8443/base',
			'http://127.0.0.1:8080',
			'http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion'
		]) {
			const parsed = parseGuardianUri(`${VALID_ID}@${url}`);
			expect(parsed.guardianId.toString('hex')).to.equal(VALID_ID);
			expect(parsed.url).to.equal(url);
		}
	});

	it('tolerates surrounding whitespace from comma-splitting', () => {
		const parsed = parseGuardianUri(`  ${VALID_ID}@https://g.example  `);
		expect(parsed.url).to.equal('https://g.example');
	});

	it('refuses every malformed shape with a precise message', () => {
		const cases: Array<[string, RegExp]> = [
			['https://no-pubkey.example', /missing the pubkey@url separator/],
			[`${VALID_ID.slice(0, 62)}@https://g.example`, /64-hex-character/],
			[`${'zz'.repeat(32)}@https://g.example`, /64-hex-character/],
			[`${'00'.repeat(32)}@https://g.example`, /not a valid x-only/],
			[`${VALID_ID}@not a url`, /not a valid URL/],
			[`${VALID_ID}@ftp://g.example`, /must use http or https/],
			[`${VALID_ID}@ws://g.example`, /must use http or https/],
			// A credential in the URL would ride into every status report
			// and log line naming the endpoint; auth is the only place for it.
			[`${VALID_ID}@https://alice:secret@g.example`, /credentials in the URL/],
			[`${VALID_ID}@https://alice@g.example`, /credentials in the URL/]
		];
		for (const [entry, message] of cases) {
			expect(() => parseGuardianUri(entry), entry).to.throw(message);
		}
	});
});

describe('Recovery assembly: parseGuardianEntry (issue #457)', () => {
	it('accepts the string form and the structured form with a credential', () => {
		const fromUri = parseGuardianEntry(`${VALID_ID}@https://g.example`);
		expect(fromUri.guardianId.toString('hex')).to.equal(VALID_ID);
		expect(fromUri.url).to.equal('https://g.example');
		expect(fromUri).to.not.have.property('auth');

		const structured = parseGuardianEntry({
			guardianId: VALID_ID,
			url: 'https://g.example',
			auth: { type: 'macaroon', macaroon: 'AgEDbG5k' }
		});
		expect(structured.guardianId.toString('hex')).to.equal(VALID_ID);
		expect(structured.auth).to.deep.equal({
			type: 'macaroon',
			macaroon: 'AgEDbG5k'
		});
	});

	it('refuses malformed structured entries with the same rules as the URI', () => {
		const cases: Array<[unknown, RegExp]> = [
			[{ url: 'https://g.example' }, /object with guardianId and url/],
			[{ guardianId: VALID_ID }, /object with guardianId and url/],
			[{ guardianId: 'zz'.repeat(32), url: 'https://g.example' }, /64-hex/],
			[{ guardianId: VALID_ID, url: 'ftp://g.example' }, /http or https/],
			[
				{ guardianId: VALID_ID, url: 'https://u:p@g.example' },
				/credentials in the URL/
			],
			[
				{ guardianId: VALID_ID, url: 'https://g.example', auth: { type: 'x' } },
				/not a known credential shape/
			],
			[
				{ guardianId: VALID_ID, url: 'https://g.example', auth: 'token' },
				/auth is not an object/
			]
		];
		for (const [entry, message] of cases) {
			expect(
				() =>
					parseGuardianEntry(entry as Parameters<typeof parseGuardianEntry>[0]),
				JSON.stringify(entry)
			).to.throw(message);
		}
	});
});

describe('Recovery assembly: guardianDescriptorFor (issue #457)', () => {
	const ONION =
		'http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion';

	it('classifies the transport from the URL the same way endpoint selection does', () => {
		const cases: Array<[string, 'https' | 'onion-http' | 'local-http']> = [
			['https://guardian.example.com:8443/base', 'https'],
			[ONION, 'onion-http'],
			['http://127.0.0.1:8080', 'local-http'],
			// Any other http host is local-http in the descriptor; whether a
			// client will dial it is allowLocalHttpHost's decision.
			['http://guardian-1:8080', 'local-http'],
			// A bare .onion suffix is not a v3 onion service.
			['http://short.onion', 'local-http']
		];
		for (const [url, type] of cases) {
			const descriptor = guardianDescriptorFor(
				parseGuardianUri(`${VALID_ID}@${url}`)
			);
			expect(descriptor, url).to.deep.equal({
				guardianId: VALID_ID,
				transports: [{ type, url }]
			});
		}
	});

	it('carries a supplied credential and omits the key otherwise', () => {
		const parsed = parseGuardianUri(`${VALID_ID}@https://g.example`);
		expect(guardianDescriptorFor(parsed)).to.not.have.property('auth');
		const withAuth = guardianDescriptorFor({
			...parsed,
			auth: { type: 'bearer', token: 'secret-token' }
		});
		expect(withAuth.auth).to.deep.equal({
			type: 'bearer',
			token: 'secret-token'
		});
	});
});

describe('Recovery assembly: buildGuardianRecovery', () => {
	it('registers a fresh namespace, runs, and confirms against the quorum', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();

		const decision = await buildGuardianRecovery({
			storage,
			nodeSecret: NODE_SECRET,
			durability: 'quorum',
			guardians: parsedGuardians(served),
			clock
		});
		expect(decision.kind).to.equal('run');
		if (decision.kind !== 'run') throw new Error('unreachable');
		expect(decision.recovery.enabled).to.equal(true);
		expect(decision.recovery.durability).to.equal('quorum');
		// The capsule locators (issue #457): the configured set, one
		// local-http transport each, no credential key when none was given.
		expect(decision.recovery.guardians).to.deep.equal(
			served.map((entry) => ({
				guardianId: entry.id.toString('hex'),
				transports: [{ type: 'local-http', url: entry.url }]
			}))
		);
		expect(decision.barrier.enforcing).to.equal(true);
		expect(decision.gate.getState()).to.equal('quarantined');
		expect(decision.gate.permitsPeerTraffic()).to.equal(false);

		const outcome = await decision.confirm();
		expect(outcome.state).to.equal('confirmed');
		expect(outcome.confirming).to.be.at.least(CRASH_V1_PROFILE.required);
		expect(decision.gate.permitsPeerTraffic()).to.equal(true);

		await shutdown(served);
		storage.close();
	});

	it('a respawn holds its lease with every guardian unreachable', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const guardians = parsedGuardians(served);

		const first = await buildGuardianRecovery({
			storage,
			nodeSecret: NODE_SECRET,
			durability: 'async-remote',
			guardians,
			clock
		});
		expect(first.kind).to.equal('run');

		// The set goes dark. The persisted lease short-circuits, so the
		// respawn decision needs no network at all; only gate confirmation
		// (which releases peer traffic) waits for the guardians to return.
		await shutdown(served);
		const respawn = await buildGuardianRecovery({
			storage,
			nodeSecret: NODE_SECRET,
			durability: 'async-remote',
			guardians,
			clock
		});
		expect(respawn.kind).to.equal('run');
		if (respawn.kind !== 'run') throw new Error('unreachable');
		expect(respawn.gate.getState()).to.equal('quarantined');

		storage.close();
	});

	it('a fresh database whose namespace the guardians hold restores, then runs', async function (): Promise<void> {
		this.timeout(30_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const guardians = parsedGuardians(served);

		// Device 1: register, run a node, commit one safety-critical frame,
		// and replicate it to the quorum.
		const storage1 = openStorage();
		const boot1 = await buildGuardianRecovery({
			storage: storage1,
			nodeSecret: NODE_SECRET,
			durability: 'quorum',
			guardians,
			clock
		});
		expect(boot1.kind).to.equal('run');
		if (boot1.kind !== 'run') throw new Error('unreachable');
		const node1 = createNode(storage1, boot1.recovery);
		expect((await boot1.confirm()).state).to.equal('confirmed');
		const commit = (
			node1 as unknown as { recovery: RecoveryManager }
		).recovery.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: sha('assembly-hash').toString('hex'),
					preimage: sha('assembly-secret')
				}
			],
			outboundMessages: []
		});
		expect(commit.committed).to.equal(true);
		await waitFor(() => boot1.replicator.replicatedThrough() >= 1n);
		node1.destroy();
		storage1.close();

		// Device 2: fresh database, same seed. Registering again would be a
		// second genesis; the decision routes to restore instead.
		const storage2 = openStorage();
		const boot2 = await buildGuardianRecovery({
			storage: storage2,
			nodeSecret: NODE_SECRET,
			durability: 'quorum',
			guardians,
			clock
		});
		expect(boot2.kind).to.equal('restore-required');
		if (boot2.kind !== 'restore-required') throw new Error('unreachable');
		expect(boot2.states.length).to.be.at.least(CRASH_V1_PROFILE.required);

		const events: string[] = [];
		const result = await boot2
			.buildRestoreDriver((event) => events.push(event.type))
			.restore();
		expect(result.framesApplied).to.be.at.least(1);
		expect(result.lease.epoch).to.equal(2n);
		expect(events).to.include('epoch:acquired');
		expect(events).to.include('restore:complete');
		// The restored preimage is the proof the state actually moved.
		expect(
			storage2.loadPreimage(sha('assembly-hash').toString('hex'))
		).to.not.equal(null);

		// The same call now answers run: the installed lease short-circuits.
		const boot3 = await buildGuardianRecovery({
			storage: storage2,
			nodeSecret: NODE_SECRET,
			durability: 'quorum',
			guardians,
			clock
		});
		expect(boot3.kind).to.equal('run');

		await shutdown(served);
		storage2.close();
	});

	it('refuses to decide without a quorum', async function (): Promise<void> {
		this.timeout(20_000);
		// Bind real ports, then close them: three configured, none reachable.
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const guardians = parsedGuardians(served);
		await shutdown(served);

		const storage = openStorage();
		const decision = await buildGuardianRecovery({
			storage,
			nodeSecret: NODE_SECRET,
			durability: 'quorum',
			guardians,
			clock
		});
		expect(decision.kind).to.equal('unavailable');
		if (decision.kind !== 'unavailable') throw new Error('unreachable');
		expect(decision.outcome).to.equal('no-quorum');
		expect(decision.detail).to.match(/only 0 of 3/);
		storage.close();
	});

	it('refuses a tor-v3-client-auth credential it has no transport for, and uses an injected one', async function (): Promise<void> {
		this.timeout(20_000);
		const served = await Promise.all([serve(0), serve(1), serve(2)]);
		const storage = openStorage();
		const guardians = parsedGuardians(served).map((g, i) =>
			i === 0
				? {
						...g,
						auth: { type: 'tor-v3-client-auth' as const, privateKey: 'x25519' }
				  }
				: g
		);
		try {
			// The HTTP client cannot apply a Tor credential; accepting the
			// key and dialing without it would be a silent downgrade.
			let refused: unknown = null;
			try {
				await buildGuardianRecovery({
					storage,
					nodeSecret: NODE_SECRET,
					durability: 'quorum',
					guardians,
					clock
				});
			} catch (err) {
				refused = err;
			}
			expect(refused).to.be.instanceOf(Error);
			expect((refused as Error).message).to.match(/tor-v3-client-auth/);

			// With a transport factory the credential has a consumer; the
			// factory sees the guardian it is for.
			const seen: string[] = [];
			const decision = await buildGuardianRecovery({
				storage,
				nodeSecret: NODE_SECRET,
				durability: 'quorum',
				guardians,
				clock,
				transportFor: (g) => {
					seen.push(g.guardianId.toString('hex'));
					return g.auth?.type === 'tor-v3-client-auth'
						? nodeGuardianTransport()
						: undefined;
				}
			});
			expect(decision.kind).to.equal('run');
			expect(seen).to.deep.equal(
				guardians.map((g) => g.guardianId.toString('hex'))
			);
			if (decision.kind === 'run') {
				expect(decision.recovery.guardians?.[0].auth).to.deep.equal({
					type: 'tor-v3-client-auth',
					privateKey: 'x25519'
				});
			}
		} finally {
			await shutdown(served);
			storage.close();
		}
	});

	it('refuses a guardian set the crash-v1 profile cannot commit to', async () => {
		const storage = openStorage();
		try {
			await expectRejects(
				buildGuardianRecovery({
					storage,
					nodeSecret: NODE_SECRET,
					durability: 'quorum',
					guardians: parsedGuardians([]).concat([
						{ guardianId: GUARDIAN_IDS[0], url: 'http://127.0.0.1:1' },
						{ guardianId: GUARDIAN_IDS[1], url: 'http://127.0.0.1:2' }
					]),
					clock
				})
			);
		} finally {
			storage.close();
		}
	});
});

async function expectRejects(promise: Promise<unknown>): Promise<void> {
	let rejected = false;
	try {
		await promise;
	} catch {
		rejected = true;
	}
	expect(rejected, 'expected the promise to reject').to.equal(true);
}
