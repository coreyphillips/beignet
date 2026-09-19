/**
 * FFOR daemon surface (issue #729): the routes exist and answer empty on a
 * node with no epoch, the witness and issuer roles switch on from options
 * (and the issuer refuses to start without the witness), the receiver
 * routes validate their parameters, and every route is in the OpenAPI
 * spec (the umbrel manager probes it). The enforcement routes take the
 * acceptStaleStateRisk acknowledgement on a capsule-restored channel, the
 * same way /channel/forceclose does, and ffor:enforce names the hold
 * (issue #908).
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { BeignetError } from '../../src/cli/errors';
import { resolveConfig } from '../../src/cli/config';
import {
	FforState,
	FforVariant,
	IFforEpochRecord
} from '../../src/lightning/ffor/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const OFFLINE = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false,
	rapidGossipSync: false,
	autoGossipSync: false,
	logLevel: 'silent' as const,
	network: 'regtest' as const,
	mnemonic: MNEMONIC,
	daemonPort: 0
};

function tmpDir(tag: string): string {
	return fs.mkdtempSync(path.join(os.tmpdir(), `beignet-ffor-${tag}-`));
}

function portOf(daemon: IStartedDaemon): number {
	return (daemon.server.address() as AddressInfo).port;
}

function request(
	port: number,
	method: string,
	urlPath: string,
	body?: unknown
): Promise<{ status: number; body: Record<string, unknown> }> {
	return new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {};
		if (payload) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
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

describe('Automatic receive funding environment', () => {
	it('requires explicit valid funding policy and preserves disabled defaults', () => {
		const saved = process.env.BEIGNET_FFOR_RECEIVE_FUNDING;
		try {
			delete process.env.BEIGNET_FFOR_RECEIVE_FUNDING;
			expect(resolveConfig({}).fforReceiveFunding).to.equal(undefined);
			for (const bad of [
				'{',
				'null',
				'[]',
				'{"enabled":"true"}',
				'{"enabled":true,"maxChannels":0}'
			]) {
				process.env.BEIGNET_FFOR_RECEIVE_FUNDING = bad;
				expect(() => resolveConfig({})).to.throw(
					/BEIGNET_FFOR_RECEIVE_FUNDING/
				);
			}
			const funding = {
				enabled: true,
				maxChannels: 2,
				maxChannelsPerPeer: 1,
				maxChannelSats: 100000,
				maxTotalSats: 200000
			};
			process.env.BEIGNET_FFOR_RECEIVE_FUNDING = JSON.stringify(funding);
			expect(resolveConfig({}).fforReceiveFunding).to.deep.equal(funding);
		} finally {
			if (saved === undefined) delete process.env.BEIGNET_FFOR_RECEIVE_FUNDING;
			else process.env.BEIGNET_FFOR_RECEIVE_FUNDING = saved;
		}
	});
});

describe('FFOR surface: configuration (issue #729)', () => {
	it('parses the BEIGNET_FFOR_* switches exactly, with their limits', () => {
		const saved = { ...process.env };
		try {
			process.env.BEIGNET_FFOR_SETTLE = 'true';
			process.env.BEIGNET_FFOR_MAX_BUDGET_MSAT = '5000000000';
			process.env.BEIGNET_FFOR_MAX_EPOCH_BLOCKS = '2016';
			process.env.BEIGNET_FFOR_FEE_BASE_MSAT = '1000';
			process.env.BEIGNET_FFOR_FEE_PPM = '5000';
			process.env.BEIGNET_FFOR_WITNESS = 'true';
			process.env.BEIGNET_FFOR_WITNESS_MAX_MAILBOXES = '8';
			process.env.BEIGNET_FFOR_ISSUER = 'true';
			const cfg = resolveConfig({}) as Record<string, unknown>;
			expect(cfg.fforSettle).to.deep.equal({
				enabled: true,
				maxBudgetMsat: '5000000000',
				maxEpochBlocks: 2016,
				feeBaseMsat: 1000,
				feePpm: 5000
			});
			expect(cfg.fforWitness).to.deep.equal({
				enabled: true,
				maxMailboxes: 8,
				maxBytes: undefined
			});
			expect(cfg.fforIssuer).to.equal(true);
			// A typo is not an opt-in.
			process.env.BEIGNET_FFOR_SETTLE = 'yes';
			process.env.BEIGNET_FFOR_WITNESS = 'on';
			process.env.BEIGNET_FFOR_ISSUER = '1';
			const off = resolveConfig({}) as Record<string, unknown>;
			expect(off.fforSettle).to.equal(undefined);
			expect(off.fforWitness).to.equal(undefined);
			expect(off.fforIssuer).to.equal(undefined);
		} finally {
			process.env = saved;
		}
	});

	it('refuses the issuer without the witness it is co-hosted with', async function () {
		this.timeout(30_000);
		const dir = tmpDir('issuer');
		let error: unknown = null;
		try {
			const daemon = await startDaemon({
				...OFFLINE,
				dataDir: dir,
				fforIssuer: true
			});
			await daemon.stop();
		} catch (e) {
			error = e;
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
		expect(error).to.be.instanceOf(BeignetError);
		expect((error as BeignetError).message).to.match(/needs fforWitness/);
	});
});

describe('FFOR surface: routes on a node with no epoch (issue #729)', () => {
	let daemon: IStartedDaemon;
	let dir: string;

	before(async function () {
		this.timeout(30_000);
		dir = tmpDir('routes');
		daemon = await startDaemon({
			...OFFLINE,
			dataDir: dir,
			fforWitness: { enabled: true, maxMailboxes: 4 },
			fforIssuer: true
		});
	});

	after(async function () {
		this.timeout(30_000);
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('lists no epochs and no settlements', async () => {
		for (const route of ['/ffor/epochs', '/ffor/settlements']) {
			const res = await request(portOf(daemon), 'GET', route);
			expect(res.status, route).to.equal(200);
			expect(res.body.result, route).to.deep.equal([]);
		}
	});

	it('serves automatic receive status and validates creation before allocating', async () => {
		const status = await request(portOf(daemon), 'GET', '/receive/status');
		expect(status.status).to.equal(200);
		expect(status.body.result).to.deep.equal({
			available: true,
			reservedChannelIds: [],
			requests: []
		});
		const quote = await request(
			portOf(daemon),
			'GET',
			'/receive/quote?peer=invalid&amountSats=20000'
		);
		expect(quote.status).to.equal(400);
		expect(quote.body.error).to.deep.include({
			code: 'INVALID_PARAMS',
			message: 'A primary node public key is required.'
		});
		const created = await request(
			portOf(daemon),
			'POST',
			'/receive/invoice',
			{}
		);
		expect(created.status).to.equal(400);
		expect(created.body.error).to.deep.include({
			code: 'INVALID_REVIEW',
			message: 'Review this payment request again.'
		});
		const small = await request(
			portOf(daemon),
			'GET',
			`/receive/quote?peer=${'02' + '33'.repeat(32)}&amountSats=1`
		);
		expect(small.status).to.equal(400);
		expect(small.body.error).to.deep.include({ code: 'AMOUNT_TOO_SMALL' });
	});
	it('reports the witness and issuer roles it runs', async () => {
		const witness = await request(
			portOf(daemon),
			'GET',
			'/ffor/witness/status'
		);
		expect(witness.body.result).to.deep.equal({ enabled: true, mailboxes: [] });
		const issuer = await request(portOf(daemon), 'GET', '/ffor/issuer/status');
		expect(issuer.body.result).to.deep.equal({ enabled: true, manifests: [] });
	});

	it('validates the receiver routes before touching any channel', async () => {
		const port = portOf(daemon);
		const epoch = await request(port, 'GET', '/ffor/epoch');
		expect(epoch.status).to.equal(400);
		const unknown = await request(
			port,
			'GET',
			'/ffor/epoch?channelId=' + 'ab'.repeat(32)
		);
		expect(unknown.status).to.equal(404);
		const start = await request(port, 'POST', '/ffor/epoch/start', {
			channelId: 'zz',
			voucherAmountsMsat: ['1000']
		});
		expect(start.status).to.equal(400);
		expect((start.body.error as { message: string }).message).to.match(
			/channelId/
		);
		const invoice = await request(port, 'POST', '/ffor/invoice', {
			channelId: 'ab'.repeat(32),
			k: 1
		});
		expect(invoice.status).to.equal(404);
		const preimage = await request(port, 'POST', '/ffor/preimage', {
			channelId: 'ab'.repeat(32),
			preimage: 'nope'
		});
		expect(preimage.status).to.equal(404);
		const offer = await request(port, 'POST', '/ffor/issuer/offer', {
			issuerNodeId: 'not-a-key',
			description: 'x'
		});
		expect(offer.status).to.equal(400);
		const enforce = await request(port, 'POST', '/ffor/enforce', {});
		expect(enforce.status).to.equal(400);
		const close = await request(port, 'POST', '/ffor/witness/close', {});
		expect(close.status).to.equal(400);
		const closeUnknown = await request(port, 'POST', '/ffor/witness/close', {
			channelId: 'ab'.repeat(32)
		});
		expect(closeUnknown.status).to.equal(404);
		const issued = await request(
			port,
			'GET',
			'/ffor/issuer/issued?issuerNodeId=' + '02' + 'ab'.repeat(32)
		);
		expect(issued.status).to.equal(400);
		const issuedUnknown = await request(
			port,
			'GET',
			'/ffor/issuer/issued?channelId=' +
				'ab'.repeat(32) +
				'&issuerNodeId=' +
				'02' +
				'ab'.repeat(32)
		);
		expect(issuedUnknown.status).to.equal(404);
	});

	it('creates a path-terminal issuer offer for a stock payer', async () => {
		const issuer = daemon.node.getNode().getNodeId();
		const res = await request(portOf(daemon), 'POST', '/ffor/issuer/offer', {
			issuerNodeId: issuer,
			description: 'ffor slots',
			amountMsat: '1000000',
			quantityMax: 3
		});
		expect(res.status).to.equal(200);
		const result = res.body.result as { offerId: string; encoded: string };
		expect(result.offerId).to.match(/^[0-9a-f]{64}$/);
		expect(result.encoded).to.match(/^lno1/);
	});

	it('is in the OpenAPI spec the umbrel manager probes', async () => {
		const res = await request(portOf(daemon), 'GET', '/openapi.json');
		expect(res.status).to.equal(200);
		const paths = Object.keys(
			(res.body as { paths: Record<string, unknown> }).paths
		);
		for (const route of [
			'/ffor/epochs',
			'/ffor/epoch/start',
			'/ffor/invoice',
			'/ffor/recover',
			'/ffor/enforce',
			'/ffor/witness/status',
			'/ffor/issuer/status',
			'/ffor/witness/close',
			'/ffor/issuer/issued'
		]) {
			expect(paths, route).to.include(route);
		}
	});
});

describe('FFOR surface: enforcement on a capsule-restored channel (issue #908)', () => {
	let daemon: IStartedDaemon;
	let dir: string;

	before(async function () {
		this.timeout(30_000);
		dir = tmpDir('enforce');
		daemon = await startDaemon({ ...OFFLINE, dataDir: dir });
	});

	after(async function () {
		this.timeout(30_000);
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	/**
	 * A role-R epoch on a fixture channel: enough of the section 7.5.5
	 * durable record for fforEnforce (role, knownPreimages) and the
	 * ffor:enforce epoch view (params, slots, witnesses) to read. One of two
	 * slots has a preimage, so preimagesKnown is 1 when the route answers.
	 */
	function epochRecord(remoteNodeId: Buffer): IFforEpochRecord {
		return {
			role: 'R',
			state: FforState.ACTIVE,
			epochId: crypto.randomBytes(32),
			params: {
				variant: FforVariant.D,
				budgetMsat: 3_000_000n,
				maxPayments: 2,
				minPaymentMsat: 1000n,
				settlementDeadline: 800_000,
				voucherExpiry: 801_000,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				escapeGranularityMsat: 1000n,
				rPerCommitmentPoints: [],
				voucherAmountsMsat: [1_000_000n, 2_000_000n]
			},
			remoteNodeId,
			initWire: Buffer.alloc(0),
			acceptWire: null,
			sCommitmentNumber: null,
			sHtlcIdBase: null,
			paymentHashes: [crypto.randomBytes(32), crypto.randomBytes(32)],
			preimages: [],
			tInit: crypto.randomBytes(32),
			tSetup: null,
			hBook: null,
			hCommit: null,
			hAct: crypto.randomBytes(32),
			epochStartHeight: 100,
			activateWire: null,
			activateAckWire: null,
			closeWire: null,
			closeAckWire: null,
			slotStates: [],
			slotUpstream: [null, null],
			settledBitmap: null,
			knownPreimages: [crypto.randomBytes(32), null],
			exposedSlots: [true, false],
			issuerProvisioned: false,
			witnesses: [],
			closeProcessed: false,
			voucherRoundFailed: false,
			unwindOwed: false,
			abortReason: null,
			closeSent: false,
			activationMismatch: true
		};
	}

	/**
	 * The recovery-surface fixture (issue #469) with a role-R epoch on it: a
	 * NORMAL channel installed straight into the manager, carrying the
	 * restoreRecencyUnproven row /channel/forceclose consults when `held`.
	 * Shared daemon, so every cell takes its channel back out.
	 */
	function installChannel(held: boolean): {
		channelId: string;
		idBuf: Buffer;
		record: IFforEpochRecord;
		remove: () => void;
	} {
		const node = daemon.node.getNode();
		const {
			createOpenerState
		} = require('../../src/lightning/channel/channel-state');
		const { Channel } = require('../../src/lightning/channel/channel');
		const {
			ChannelState,
			DEFAULT_CHANNEL_CONFIG
		} = require('../../src/lightning/channel/types');
		const { getPublicKey } = require('../../src/lightning/crypto/ecdh');
		const point = getPublicKey(crypto.randomBytes(32));
		const bp = {
			fundingPubkey: point,
			revocationBasepoint: point,
			paymentBasepoint: point,
			delayedPaymentBasepoint: point,
			htlcBasepoint: point,
			firstPerCommitmentPoint: point
		};
		const state = createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: 100_000n,
			pushMsat: 0n,
			localConfig: DEFAULT_CHANNEL_CONFIG,
			localBasepoints: bp,
			localPerCommitmentSeed: crypto.randomBytes(32)
		});
		state.state = ChannelState.NORMAL;
		state.channelId = crypto.randomBytes(32);
		state.fundingTxid = crypto.randomBytes(32);
		state.remoteBasepoints = bp;
		if (held) state.restoreRecencyUnproven = true;
		const peer = getPublicKey(crypto.randomBytes(32));
		const record = epochRecord(peer);
		state.ffor = record;
		node
			.getChannelManager()
			.restoreChannel(new Channel(state), peer.toString('hex'));
		const channelId = state.channelId.toString('hex');
		return {
			channelId,
			idBuf: state.channelId,
			record,
			remove: (): void => {
				(
					node.getChannelManager() as unknown as {
						channels: Map<string, unknown>;
					}
				).channels.delete(channelId);
			}
		};
	}

	function errorOf(res: { body: Record<string, unknown> }): {
		code?: string;
		message?: string;
	} {
		return (res.body.error as { code?: string; message?: string }) ?? {};
	}

	it('POST /ffor/enforce refuses a held channel without acceptStaleStateRisk and admits it with the exact flag', async () => {
		const fx = installChannel(true);
		try {
			const port = portOf(daemon);
			// Before the fix the refusal named a field this route could not
			// accept, so a held channel had no operator remedy at all.
			const refused = await request(port, 'POST', '/ffor/enforce', {
				channelId: fx.channelId
			});
			expect(refused.status).to.equal(400);
			expect(errorOf(refused).code).to.equal('INVALID_PARAMS');
			expect(errorOf(refused).message).to.match(/acceptStaleStateRisk/);

			// Strict boolean, the /channel/forceclose rule (issue #469): the
			// acknowledgement is authorization, so a truthy value is not it.
			for (const spelling of ['true', 1]) {
				const res = await request(port, 'POST', '/ffor/enforce', {
					channelId: fx.channelId,
					acceptStaleStateRisk: spelling
				});
				const label = `acceptStaleStateRisk ${JSON.stringify(spelling)}`;
				expect(res.status, label).to.equal(400);
				expect(errorOf(res).code, label).to.equal('INVALID_PARAMS');
				expect(errorOf(res).message, label).to.match(/acceptStaleStateRisk/);
			}

			// With the acknowledgement the call reaches forceCloseChannel and
			// answers with the enforce shape: whatever the engine says about
			// this fixture's commitment, the hold is no longer what stops it.
			const accepted = await request(port, 'POST', '/ffor/enforce', {
				channelId: fx.channelId,
				acceptStaleStateRisk: true
			});
			expect(accepted.status).to.equal(200);
			expect(errorOf(accepted).message ?? '').to.not.match(
				/acceptStaleStateRisk/
			);
			const result = accepted.body.result as Record<string, unknown>;
			expect(result).to.have.property('ok');
			expect(result.preimagesKnown).to.equal(1);
			expect(String(result.error ?? '')).to.not.match(/acceptStaleStateRisk/);
		} finally {
			fx.remove();
		}
	});

	it('POST /ffor/enforce on a channel that is not held is unchanged with or without the flag', async () => {
		const fx = installChannel(false);
		try {
			const port = portOf(daemon);
			for (const body of [
				{ channelId: fx.channelId },
				{ channelId: fx.channelId, acceptStaleStateRisk: true },
				{ channelId: fx.channelId, acceptStaleStateRisk: 'true' }
			]) {
				const res = await request(port, 'POST', '/ffor/enforce', body);
				const label = JSON.stringify(body);
				expect(res.status, label).to.equal(200);
				const result = res.body.result as Record<string, unknown>;
				expect(result, label).to.have.property('ok');
				expect(result.preimagesKnown, label).to.equal(1);
				expect(String(result.error ?? ''), label).to.not.match(
					/acceptStaleStateRisk/
				);
			}
		} finally {
			fx.remove();
		}
	});

	it('POST /ffor/recover with forceCloseIfUnreachable demands the same acknowledgement on a held channel only', async () => {
		const held = installChannel(true);
		const plain = installChannel(false);
		try {
			const port = portOf(daemon);
			// forceCloseIfUnreachable reaches channelManager.forceClose with
			// no held check of its own: the same commitment, the same flag.
			for (const flag of [undefined, 'true', 1]) {
				const res = await request(port, 'POST', '/ffor/recover', {
					channelId: held.channelId,
					forceCloseIfUnreachable: true,
					...(flag === undefined ? {} : { acceptStaleStateRisk: flag })
				});
				const label = `acceptStaleStateRisk ${JSON.stringify(flag)}`;
				expect(res.status, label).to.equal(400);
				expect(errorOf(res).code, label).to.equal('INVALID_PARAMS');
				expect(errorOf(res).message, label).to.match(/acceptStaleStateRisk/);
			}
			const acknowledged = await request(port, 'POST', '/ffor/recover', {
				channelId: held.channelId,
				forceCloseIfUnreachable: true,
				acceptStaleStateRisk: true
			});
			expect(errorOf(acknowledged).message ?? '').to.not.match(
				/acceptStaleStateRisk/
			);
			// Without the force-close request there is nothing to acknowledge:
			// the witness fetch and the cooperative path are as before.
			const passive = await request(port, 'POST', '/ffor/recover', {
				channelId: held.channelId
			});
			expect(errorOf(passive).message ?? '').to.not.match(
				/acceptStaleStateRisk/
			);
			// A channel that is not held never asks for the flag.
			const unheld = await request(port, 'POST', '/ffor/recover', {
				channelId: plain.channelId,
				forceCloseIfUnreachable: true
			});
			expect(errorOf(unheld).message ?? '').to.not.match(
				/acceptStaleStateRisk/
			);
		} finally {
			held.remove();
			plain.remove();
		}
	});

	it('ffor:enforce carries restoreRecencyUnproven: true for a held channel only', async () => {
		const held = installChannel(true);
		const plain = installChannel(false);
		const events: Array<{
			channelId: string;
			epoch: Record<string, unknown>;
			restoreRecencyUnproven?: true;
		}> = [];
		const listener = (e: (typeof events)[number]): void => {
			events.push(e);
		};
		daemon.node.on('ffor:enforce', listener);
		try {
			// The manager's escalation (section 7.5.5) arrives at BeignetNode
			// through LightningNode's relay; drive that relay directly.
			const inner = daemon.node.getNode();
			inner.emit('ffor:enforce', {
				channelId: held.idBuf,
				record: held.record
			});
			inner.emit('ffor:enforce', {
				channelId: plain.idBuf,
				record: plain.record
			});
			expect(events).to.have.length(2);
			expect(events[0].channelId).to.equal(held.channelId);
			expect(events[0].restoreRecencyUnproven).to.equal(true);
			expect(events[0].epoch.state).to.equal('ACTIVE');
			expect(events[1].channelId).to.equal(plain.channelId);
			expect(events[1]).to.not.have.property('restoreRecencyUnproven');
			expect(events[1].epoch.activationMismatch).to.equal(true);
		} finally {
			daemon.node.off('ffor:enforce', listener);
			held.remove();
			plain.remove();
		}
	});

	it('declares the flag and the refusal on both routes in the OpenAPI spec', async () => {
		const res = await request(portOf(daemon), 'GET', '/openapi.json');
		expect(res.status).to.equal(200);
		const paths = (res.body as { paths: Record<string, unknown> }).paths;
		for (const route of ['/ffor/enforce', '/ffor/recover']) {
			const post = (paths[route] as { post: Record<string, unknown> }).post;
			const schema = (
				post.requestBody as {
					content: {
						'application/json': {
							schema: {
								properties: Record<string, { type: string }>;
								required?: string[];
							};
						};
					};
				}
			).content['application/json'].schema;
			expect(schema.properties.acceptStaleStateRisk, route).to.deep.equal({
				type: 'boolean'
			});
			expect(schema.required ?? [], route).to.not.include(
				'acceptStaleStateRisk'
			);
			expect(post.responses, route).to.have.property('400');
			expect(post.summary, route).to.match(/acceptStaleStateRisk/);
		}
	});
});
