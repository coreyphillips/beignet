/**
 * FFOR daemon surface (issue #729): the routes exist and answer empty on a
 * node with no epoch, the witness and issuer roles switch on from options
 * (and the issuer refuses to start without the witness), the receiver
 * routes validate their parameters, and every route is in the OpenAPI
 * spec (the umbrel manager probes it). The enforcement routes take the
 * acceptStaleStateRisk acknowledgement on either recency hold, the
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
import { InvalidRequestError } from '../../src/lightning/node/types';
const sinon = require('sinon');
import {
	FforState,
	FforVariant,
	IFforEpochRecord
} from '../../src/lightning/ffor/types';
import { decodeRequestEnvelope } from '../../src/lightning/direct-funding/envelope';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';

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

	it('serves automatic receive status and validates creation before preparing anything', async () => {
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
		// No channel with this peer, so the amount is measured against the
		// direct-funding minimum and the refusal names it.
		const small = await request(
			portOf(daemon),
			'GET',
			`/receive/quote?peer=${'02' + '33'.repeat(32)}&amountSats=1`
		);
		expect(small.status).to.equal(400);
		expect(small.body.error).to.deep.include({ code: 'AMOUNT_TOO_SMALL' });
		expect((small.body.error as { message: string }).message).to.contain(
			'5000'
		);
		// And a peer nobody is connected to refuses in either mode.
		const away = await request(
			portOf(daemon),
			'GET',
			`/receive/quote?peer=${'02' + '33'.repeat(32)}&amountSats=20000`
		);
		expect(away.status).to.equal(409);
		expect(away.body.error).to.deep.include({ code: 'RECEIVE_UNAVAILABLE' });
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

describe('FFOR surface: enforcement on recency-held channels (issues #908 and #907)', () => {
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
	 * channel installed straight into the manager with the requested hold.
	 * A reestablish hold uses ERRORED, as the invalid-secret handler does.
	 * Shared daemon, so every cell takes its channel back out.
	 */
	function installChannel(held: boolean | 'reestablish' | 'both'): {
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
		if (held === true || held === 'both') state.restoreRecencyUnproven = true;
		if (held === 'reestablish' || held === 'both') {
			state.reestablishRecencyUnproven = true;
			state.state = ChannelState.ERRORED;
		}
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

	it('all force-close routes require exact acknowledgement for a reestablish hold', async () => {
		const inner = daemon.node.getNode();
		const forceClose = sinon.spy(inner.getChannelManager(), 'forceClose');
		const recover = sinon.spy(inner, 'rescueFforEpoch');
		try {
			for (const hold of ['reestablish', 'both'] as const) {
				const fx = installChannel(hold);
				try {
					for (const route of [
						'/ffor/recover',
						'/ffor/enforce',
						'/channel/forceclose'
					]) {
						const body = {
							channelId: fx.channelId.toUpperCase(),
							...(route === '/ffor/recover'
								? { forceCloseIfUnreachable: true }
								: {})
						};
						for (const flag of [undefined, false, 'true', 1]) {
							forceClose.resetHistory();
							recover.resetHistory();
							const res = await request(portOf(daemon), 'POST', route, {
								...body,
								...(flag === undefined ? {} : { acceptStaleStateRisk: flag })
							});
							expect(res.status, route).to.equal(400);
							expect(errorOf(res).code).to.equal('INVALID_PARAMS');
							expect(errorOf(res).message).to.match(/acceptStaleStateRisk/);
							if (hold === 'reestablish') {
								expect(errorOf(res).message).to.match(
									/claimed at channel_reestablish/
								);
								expect(errorOf(res).message).to.not.match(/Recovery Capsule/);
							}
							expect(
								forceClose.called,
								`${route}: no commitment construction`
							).to.equal(false);
							expect(
								recover.called,
								`${route}: no recovery before acknowledgement`
							).to.equal(false);
						}
						const accepted = await request(portOf(daemon), 'POST', route, {
							...body,
							acceptStaleStateRisk: true
						});
						// This fixture has no remote commitment signature. The channel
						// route surfaces that engine refusal as 500; FFOR returns its result.
						expect(accepted.status, route).to.equal(
							route === '/channel/forceclose' ? 500 : 200
						);
						expect(errorOf(accepted).message ?? '').to.not.match(
							/acceptStaleStateRisk/
						);
						expect(
							forceClose.calledOnce,
							`${route}: acknowledged engine exit`
						).to.equal(true);
					}
					forceClose.resetHistory();
					const passive = await request(
						portOf(daemon),
						'POST',
						'/ffor/recover',
						{
							channelId: fx.channelId
						}
					);
					expect(passive.status).to.equal(200);
					expect(forceClose.called, 'passive recovery never closes').to.equal(
						false
					);
				} finally {
					fx.remove();
				}
			}
		} finally {
			recover.restore();
			forceClose.restore();
		}
	});

	it('rechecks a hold that arrives during witness retrieval before force closing', async () => {
		const inner = daemon.node.getNode();
		for (const flag of [undefined, 'true', 1, true]) {
			const fx = installChannel(false);
			fx.record.witnesses = [
				{
					witnessNodeId: fx.record.remoteNodeId,
					mailboxId: crypto.randomBytes(32),
					fetchPrivkey: crypto.randomBytes(32),
					encPrivkey: crypto.randomBytes(32),
					retentionUntil: 802_000,
					minReceipts: 1,
					manifestWire: Buffer.alloc(0),
					ackedAt: 1
				}
			];
			let release!: () => void;
			let entered!: () => void;
			const waiting = new Promise<void>((resolve) => {
				release = resolve;
			});
			const started = new Promise<void>((resolve) => {
				entered = resolve;
			});
			const fetch = sinon
				.stub(inner, 'fetchFforWitnessRecords')
				.callsFake(async () => {
					entered();
					await waiting;
					return [];
				});
			const forceClose = sinon.spy(inner.getChannelManager(), 'forceClose');
			try {
				const pending = request(portOf(daemon), 'POST', '/ffor/recover', {
					channelId: fx.channelId,
					forceCloseIfUnreachable: true,
					...(flag === undefined ? {} : { acceptStaleStateRisk: flag })
				});
				await started;
				const { ChannelState } = require('../../src/lightning/channel/types');
				Object.assign(
					inner.getChannelManager().getChannel(fx.idBuf)!.getFullState(),
					{
						reestablishRecencyUnproven: true,
						state: ChannelState.ERRORED
					}
				);
				release();
				const result = await pending;
				if (flag === true) {
					expect(result.status).to.equal(200);
					expect(forceClose.calledOnce).to.equal(true);
				} else {
					expect(result.status).to.equal(400);
					expect(errorOf(result).code).to.equal('INVALID_PARAMS');
					expect(errorOf(result).message).to.match(
						/claimed at channel_reestablish/
					);
					expect(errorOf(result).message).to.match(/acceptStaleStateRisk/);
					expect(forceClose.called).to.equal(false);
				}
			} finally {
				release();
				fetch.restore();
				forceClose.restore();
				fx.remove();
			}
		}
	});

	it('direct FFOR recovery also requires exact acknowledgement for either hold', async () => {
		const inner = daemon.node.getNode();
		const forceClose = sinon.spy(inner.getChannelManager(), 'forceClose');
		try {
			for (const hold of [true, 'reestablish'] as const) {
				const fx = installChannel(hold);
				try {
					const { ChannelState } = require('../../src/lightning/channel/types');
					inner.getChannelManager().getChannel(fx.idBuf)!.getFullState().state =
						ChannelState.ERRORED;
					for (const flag of [undefined, false, 'true', 1]) {
						forceClose.resetHistory();
						let refusal: unknown;
						try {
							await inner.rescueFforEpoch(fx.channelId, {
								forceCloseIfUnreachable: true,
								acceptStaleStateRisk: flag as boolean | undefined,
								destinationScript: Buffer.from('0014' + '22'.repeat(20), 'hex')
							});
						} catch (err) {
							refusal = err;
						}
						expect(refusal).to.be.instanceOf(InvalidRequestError);
						expect((refusal as Error).message).to.match(/acceptStaleStateRisk/);
						expect(forceClose.called).to.equal(false);
					}
				} finally {
					fx.remove();
				}
			}
		} finally {
			forceClose.restore();
		}
	});

	it('ffor:enforce reports both hold origins independently', async () => {
		const held = installChannel(true);
		const reestablish = installChannel('reestablish');
		const both = installChannel('both');
		const plain = installChannel(false);
		const events: Array<{
			channelId: string;
			epoch: Record<string, unknown>;
			restoreRecencyUnproven?: true;
			reestablishRecencyUnproven?: true;
		}> = [];
		const listener = (e: (typeof events)[number]): void => {
			events.push(e);
		};
		daemon.node.on('ffor:enforce', listener);
		try {
			// The manager's escalation (section 7.5.5) arrives at BeignetNode
			// through LightningNode's relay; drive that relay directly.
			const inner = daemon.node.getNode();
			for (const fx of [held, reestablish, both, plain]) {
				inner.emit('ffor:enforce', { channelId: fx.idBuf, record: fx.record });
			}
			expect(events).to.have.length(4);
			expect(events[0].channelId).to.equal(held.channelId);
			expect(events[0].restoreRecencyUnproven).to.equal(true);
			expect(events[0]).to.not.have.property('reestablishRecencyUnproven');
			expect(events[0].epoch.state).to.equal('ACTIVE');
			expect(events[1].channelId).to.equal(reestablish.channelId);
			expect(events[1]).to.not.have.property('restoreRecencyUnproven');
			expect(events[1].reestablishRecencyUnproven).to.equal(true);
			expect(events[2].restoreRecencyUnproven).to.equal(true);
			expect(events[2].reestablishRecencyUnproven).to.equal(true);
			expect(events[3].channelId).to.equal(plain.channelId);
			expect(events[3]).to.not.have.property('restoreRecencyUnproven');
			expect(events[3]).to.not.have.property('reestablishRecencyUnproven');
			expect(events[3].epoch.activationMismatch).to.equal(true);
		} finally {
			daemon.node.off('ffor:enforce', listener);
			held.remove();
			reestablish.remove();
			both.remove();
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

/**
 * The 2026-09-20 rule: automatic offline receive is only for a channel that
 * already exists with the peer. With none, the route hands back a direct-funding
 * request rather than asking the peer to open one, so a wallet can still be paid
 * without this flow ever opening a channel.
 */
describe('automatic receive falls back to direct funding', function () {
	this.timeout(30_000);
	let daemon: IStartedDaemon;
	let dir: string;
	let port: number;
	// Real curve points: the request envelope builds a blinded path through the
	// configured liquidity peer, so a made-up pubkey cannot be minted against.
	const lsp =
		'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
	const stranger =
		'02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
	let peers: { pubkey: string; host: string; port: number; state: string }[];

	before(async function () {
		this.timeout(30_000);
		dir = tmpDir('receive-df');
		daemon = await startDaemon({ ...OFFLINE, dataDir: dir });
		port = portOf(daemon);
		// The route only needs to know the peer is there and where it is: it never
		// talks to the peer in this mode, which is the point of the fallback.
		peers = [{ pubkey: lsp, host: '10.0.0.7', port: 9736, state: 'ready' }];
		sinon.stub(daemon.node, 'listPeers').callsFake(() => peers);
	});

	after(async function () {
		this.timeout(30_000);
		sinon.restore();
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('quotes direct funding without contacting the peer', async () => {
		const res = await request(
			port,
			'GET',
			`/receive/quote?peer=${lsp}&amountSats=120000`
		);
		expect(res.status).to.equal(200);
		const quote = res.body.result as Record<string, unknown>;
		expect(quote).to.include({
			available: true,
			mode: 'direct-funding',
			peer: lsp,
			amountSats: 120_000,
			feeSats: 0,
			minAmountSat: 5_000
		});
		expect(quote).to.not.have.property('terms');
		expect(quote.expiresAt).to.be.a('number');
	});

	it('mints a payable request, configures the peer and reserves nothing', async () => {
		const quoted = await request(
			port,
			'GET',
			`/receive/quote?peer=${lsp}&amountSats=120000`
		);
		const body = {
			peer: lsp,
			amountSats: 120_000,
			description: 'coffee',
			requestId: 'daemon-receive-0001',
			quote: quoted.body.result
		};
		const created = await request(port, 'POST', '/receive/invoice', body);
		expect(created.status).to.equal(200);
		const result = created.body.result as Record<string, unknown>;
		expect(result).to.include({
			kind: 'direct-funding',
			peer: lsp,
			amountSats: 120_000,
			offlineReceive: false
		});
		// What a payer actually gets: an envelope this node signed, for this
		// amount, carrying the receipt hash the route reported.
		const env = decodeRequestEnvelope(result.request as string);
		expect(env.receiverNodeId.toString('hex')).to.equal(
			daemon.node.getInfo().nodeId
		);
		expect(env.amountSat).to.equal(120_000n);
		expect(env.receiptHash.toString('hex')).to.equal(result.paymentHash);

		// Direct funding now points at this peer, on the address it is connected
		// on, with every other setting left at its default.
		const config = await request(port, 'GET', '/direct-funding/config');
		expect(config.body.result).to.deep.equal({
			lspPubkey: lsp,
			lspHost: '10.0.0.7',
			lspPort: 9736,
			targetInboundSat: 0,
			trusted: false,
			allowSplice: false,
			allowUnpairedSplice: false,
			unpairedSpliceDepth: 3,
			minAmountSat: 5_000
		});

		// No epoch and no reservation: the job is durable but holds nothing.
		const status = await request(port, 'GET', '/receive/status');
		const listed = status.body.result as {
			reservedChannelIds: string[];
			requests: Record<string, unknown>[];
		};
		expect(listed.reservedChannelIds).to.deep.equal([]);
		expect(listed.requests).to.have.length(1);
		expect(listed.requests[0]).to.include({
			id: 'daemon-receive-0001',
			kind: 'direct-funding',
			peer: lsp,
			amountSats: 120_000
		});
		expect(listed.requests[0].channelId).to.equal(undefined);
		expect(
			(await request(port, 'GET', '/ffor/epochs')).body.result
		).to.deep.equal([]);

		// Retrying the same id hands back the same envelope rather than a second.
		const retry = await request(port, 'POST', '/receive/invoice', body);
		expect(retry.status).to.equal(200);
		expect(retry.body.result).to.deep.equal(result);
	});

	it('refuses a second peer rather than retargeting the configured one', async () => {
		peers = [
			...peers,
			{ pubkey: stranger, host: '10.0.0.8', port: 9737, state: 'connected' }
		];
		const quoted = await request(
			port,
			'GET',
			`/receive/quote?peer=${stranger}&amountSats=120000`
		);
		expect(quoted.status).to.equal(200);
		const created = await request(port, 'POST', '/receive/invoice', {
			peer: stranger,
			amountSats: 120_000,
			requestId: 'daemon-receive-0002',
			quote: quoted.body.result
		});
		expect(created.status).to.equal(409);
		expect(created.body.error).to.deep.include({
			code: 'RECEIVE_UNAVAILABLE'
		});
		expect((created.body.error as { message: string }).message).to.contain(
			'another peer'
		);
		const config = await request(port, 'GET', '/direct-funding/config');
		expect((config.body.result as { lspPubkey: string }).lspPubkey).to.equal(
			lsp
		);
	});
});

/**
 * Issue #920: in bolt11 mode the receive routes ask the settlement peer for
 * its terms, and a peer that refuses (one that does not run the settle role)
 * used to reach the wallet as a 500 "Internal server error". The refusal is
 * the peer's to explain, so it comes back as a 409 in the peer's own words.
 */
describe('automatic receive surfaces a settlement peer refusal (issue #920)', function () {
	this.timeout(30_000);
	let daemon: IStartedDaemon;
	let dir: string;
	let port: number;
	// bolt11 mode builds no envelope, so the key only has to look like one.
	const primary = '02' + '5a'.repeat(32);
	const refusal = 'Your node does not provide offline receiving.';
	/** Every receive request the stubbed transport carried to the peer. */
	let asked: Record<string, unknown>[];

	before(async function () {
		this.timeout(30_000);
		dir = tmpDir('receive-refusal');
		daemon = await startDaemon({ ...OFFLINE, dataDir: dir });
		port = portOf(daemon);
	});

	// Scoped to each test: the daemon's background loops read the channel list
	// too, and must not see this made-up channel outside the request under test.
	beforeEach(() => {
		asked = [];
		sinon
			.stub(daemon.node, 'listPeers')
			.returns([
				{ pubkey: primary, host: '10.0.0.9', port: 9735, state: 'ready' }
			]);
		// Nothing spendable on our side and room to receive: the shape that puts
		// the request on the bolt11 route, where the peer is asked for terms.
		sinon.stub(daemon.node, 'listChannels').returns([
			{
				channelId: '6b'.repeat(32),
				peerPubkey: primary,
				state: 'NORMAL',
				htlcUsable: true,
				localBalanceSats: 0,
				remoteBalanceSats: 200_000
			}
		]);
		const ln = daemon.node.getNode();
		sinon
			.stub(ln, 'sendCustomMessage')
			.callsFake((to: string, subtype: number, payload: Buffer) => {
				if (
					to !== primary ||
					subtype !== BeignetCustomSubtype.FFOR_RECEIVE_REQUEST
				)
					return;
				const body = JSON.parse(payload.toString('utf8'));
				asked.push(body);
				setImmediate(() =>
					ln.emit('custom-message', {
						peerPubkey: primary,
						version: 1,
						subtype: BeignetCustomSubtype.FFOR_RECEIVE_RESPONSE,
						payload: Buffer.from(
							JSON.stringify({ id: body.id, ok: false, error: refusal })
						)
					})
				);
			});
	});

	afterEach(() => sinon.restore());

	after(async function () {
		this.timeout(30_000);
		await daemon.stop();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("GET /receive/quote answers 409 with the peer's own message", async () => {
		const res = await request(
			port,
			'GET',
			`/receive/quote?peer=${primary}&amountSats=20000`
		);
		expect(asked.map((b) => b.op)).to.deep.equal(['quote']);
		expect(res.status).to.equal(409);
		expect(res.body.error).to.deep.equal({
			code: 'RECEIVE_UNAVAILABLE',
			message: refusal
		});
	});

	it('POST /receive/invoice answers the same and keeps no request', async () => {
		const res = await request(port, 'POST', '/receive/invoice', {
			peer: primary,
			amountSats: 20_000,
			requestId: 'daemon-refusal-0001',
			quote: {
				peer: primary,
				amountSats: 20_000,
				terms: { feeBaseMsat: 0, feePpm: 0 },
				expiresAt: Date.now() + 60_000
			}
		});
		expect(asked.map((b) => b.op)).to.deep.equal(['quote']);
		expect(res.status).to.equal(409);
		expect(res.body.error).to.deep.equal({
			code: 'RECEIVE_UNAVAILABLE',
			message: refusal
		});
		const status = await request(port, 'GET', '/receive/status');
		expect(status.body.result).to.deep.include({
			reservedChannelIds: [],
			requests: []
		});
	});
});
