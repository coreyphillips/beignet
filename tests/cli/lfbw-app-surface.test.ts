/**
 * LFBW app surface reconciliation (issue #614, workstream 5A of #532).
 *
 * Phases 1 through 4 were written one workstream at a time against a moving
 * target. Every assertion here is a call the LFBW app already makes against a
 * daemon it spawns, pinned so a rename or a dropped parameter fails here
 * rather than in a wallet that shows the wrong number. Much of what is pinned
 * fails SILENTLY in the app: an SSE event is bound by name and a rename just
 * stops updating the UI, and a refusal served as a 200 reads as a success.
 *
 * The behaviour behind these rows is tested by the workstream that added it;
 * direct-funding-config.test.ts (4D) covers the configure merge, the minimum
 * clamp and the BEIGNET_DF_* resolution, and direct-funding-envelope.test.ts
 * (4A) covers the envelope against a fixture. What is here is the app's view of
 * it: the parameter names it posts, the field names it reads back, and the one
 * envelope check #614 asks for against a live daemon rather than a fixture.
 */

import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { expect } from 'chai';

import {
	formatSseFrame,
	getRelayedEvents,
	startDaemon
} from '../../src/cli/daemon';
import { getOpenApiSpec } from '../../src/cli/openapi';
import { resolveConfig } from '../../src/cli/config';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Channel } from '../../src/lightning/channel/channel';

const SRC = path.join(__dirname, '../..', 'src');
const read = (rel: string): string =>
	fs.readFileSync(path.join(SRC, rel), 'utf8');

const daemonSrc = read('cli/daemon.ts');
const typesSrc = read('cli/types.ts');
const beignetNodeSrc = read('cli/beignet-node.ts');

type Schema = Record<string, unknown>;
type Operation = {
	summary?: string;
	requestBody?: { content?: Record<string, { schema?: Schema }> };
	responses?: Record<string, { content?: Record<string, { schema?: Schema }> }>;
};
type Spec = {
	paths: Record<string, Record<string, Operation>>;
	components: { schemas: Record<string, Schema> };
};
const spec = getOpenApiSpec() as unknown as Spec;

/** Follow a $ref, so a route documented by reference reads like an inline one. */
function resolveSchema(schema?: Schema): Schema | undefined {
	if (!schema) return undefined;
	const ref = schema.$ref;
	if (typeof ref === 'string') {
		return resolveSchema(
			spec.components.schemas[ref.split('/').pop() as string]
		);
	}
	return schema;
}

function propertiesOf(schema?: Schema): string[] {
	const resolved = resolveSchema(schema);
	if (!resolved) return [];
	// A composed shape (allOf) and a list of them (items) both hide the field
	// names one level down; a scan that stops at the top sees neither.
	if (Array.isArray(resolved.allOf)) {
		return (resolved.allOf as Schema[]).flatMap((member) =>
			propertiesOf(member)
		);
	}
	if (!resolved.properties && resolved.items) {
		return propertiesOf(resolved.items as Schema);
	}
	return Object.keys((resolved.properties ?? {}) as Schema);
}

/** Body parameters a route documents; empty for a route that takes no body. */
function requestParams(route: string, method = 'post'): string[] {
	const op = spec.paths[route]?.[method];
	expect(op, `${method.toUpperCase()} ${route} is missing from the spec`).to
		.exist;
	return propertiesOf(op?.requestBody?.content?.['application/json']?.schema);
}

/** Fields a route's 200 documents; empty for a non-JSON or absent one. */
function responseFields(route: string, method = 'post'): string[] {
	const op = spec.paths[route]?.[method];
	return propertiesOf(
		op?.responses?.['200']?.content?.['application/json']?.schema
	);
}

/** Every (method, route) pair in the spec. */
function everyOperation(): Array<[string, string]> {
	const out: Array<[string, string]> = [];
	for (const [route, ops] of Object.entries(spec.paths)) {
		for (const method of Object.keys(ops)) out.push([method, route]);
	}
	return out;
}

/** The body of one daemon route handler, for the parameters it destructures. */
function handlerSource(routeKey: string, span = 2000): string {
	const start = daemonSrc.indexOf(`'${routeKey}':`);
	expect(start, `${routeKey} is not a daemon route`).to.be.greaterThan(-1);
	return daemonSrc.slice(start, start + span);
}

/** A declaration block from a source file, for its field names. */
function declaration(src: string, needle: string, span = 500): string {
	const at = src.indexOf(needle);
	expect(at, needle).to.be.greaterThan(-1);
	return src.slice(at, at + span);
}

describe('LFBW app surface (issue #614)', () => {
	describe('routes and parameters', () => {
		// 1A, issue #534. Without the address the app has to splice out to its
		// own wallet and pay a second on-chain transaction to forward it.
		it('POST /channel/splice-out takes address beside the three required fields', () => {
			expect(requestParams('/channel/splice-out')).to.include.members([
				'channelId',
				'amountSats',
				'feeratePerkw',
				'address'
			]);
			expect(handlerSource('POST /channel/splice-out')).to.include('address');
		});

		// 1B, issue #536.
		it('POST /channel/open-v2 takes requestFunds and maxLeaseRates', () => {
			expect(requestParams('/channel/open-v2')).to.include.members([
				'requestFunds',
				'maxLeaseRates'
			]);
			const body = resolveSchema(
				spec.paths['/channel/open-v2'].post.requestBody?.content?.[
					'application/json'
				]?.schema
			);
			const requestFunds = (body?.properties as Schema).requestFunds as Schema;
			expect(propertiesOf(requestFunds)).to.have.members([
				'requestedSats',
				'blockheight'
			]);
			const handler = handlerSource('POST /channel/open-v2');
			expect(handler).to.include('requestFunds');
			expect(handler).to.include('maxLeaseRates');
		});

		// The app pre-budgets amountSats against its own lease-fee ceiling and
		// skips the open entirely while GET /info reports blockHeight 0, so the
		// field has to be the node's real height rather than a placeholder.
		it('GET /info reports the chain height the node actually has', () => {
			expect(
				declaration(beignetNodeSrc, 'getInfo(): NodeInfo {', 900)
			).to.include('blockHeight: this.node.getCurrentBlockHeight()');
			expect(responseFields('/info', 'get')).to.include('blockHeight');
		});

		// 3B, issue #595. The app sends exactly 72, and only on the splice-hold
		// fallback path.
		it('POST /invoice/create takes minFinalCltvExpiry and passes it through', () => {
			expect(requestParams('/invoice/create')).to.include('minFinalCltvExpiry');
			// Last positional argument of createInvoice, not dropped on the floor.
			expect(handlerSource('POST /invoice/create')).to.match(
				/createInvoice\([^)]*minFinalCltvExpiry/s
			);
		});

		// 3B, issue #595. The app posts three fields and reads two back.
		it('POST /jit/invoice takes lspPubkey, amountSats and description', () => {
			expect(requestParams('/jit/invoice')).to.include.members([
				'lspPubkey',
				'amountSats',
				'description'
			]);
			expect(handlerSource('POST /jit/invoice')).to.include(
				"if (!lspPubkey) return failure('INVALID_PARAMS'"
			);
		});

		it('POST /jit/invoice answers with the quoted fee', () => {
			expect(responseFields('/jit/invoice')).to.include.members([
				'flatFeeSat',
				'feePpm'
			]);
		});

		// The app sends neither expirySecs nor targetRemainingInboundSat, so
		// both defaults are load bearing: an omitted expiry has to reach the
		// library's own default rather than arrive as an explicit undefined,
		// and the inbound target has to mean "leave none over".
		it('POST /jit/invoice defaults the two fields the app omits', () => {
			const create = declaration(
				beignetNodeSrc,
				'async createJitInvoice(opts: {',
				2500
			);
			expect(create).to.include(
				'...(opts.expirySecs !== undefined ? { expiry: opts.expirySecs } : {})'
			);
			expect(create).to.include('opts.targetRemainingInboundSat ?? 0');
		});

		// The app's call timeout is 20s. The intent exchange is the only
		// unbounded thing in the route, so its own ack timeout has to land
		// inside that, or the app gives up on a request the LSP still answers.
		it('the JIT intent ack times out inside the app 20s call timeout', () => {
			const match = read('lightning/node/lightning-node.ts').match(
				/const JIT_RECEIVE_ACK_TIMEOUT_MS = ([\d_]+);/
			);
			expect(match, 'JIT_RECEIVE_ACK_TIMEOUT_MS').to.exist;
			expect(Number(match![1].replace(/_/g, ''))).to.be.lessThan(20_000);
		});

		// 4D, issue #613. The dashboard posts {minAmountSat} alone and then
		// requires lspPubkey in the readback, and the app's manager posts the
		// other five without minAmountSat, so the route has to MERGE. Both
		// halves of that are in the handler: it destructures each field and
		// spreads it only when the caller named it.
		it('POST /direct-funding/configure takes the six fields and merges them', () => {
			const fields = [
				'lspPubkey',
				'lspHost',
				'lspPort',
				'targetInboundSat',
				'trusted',
				'minAmountSat'
			];
			expect(requestParams('/direct-funding/configure')).to.include.members(
				fields
			);
			const handler = handlerSource('POST /direct-funding/configure', 1400);
			for (const field of fields) {
				expect(handler, `${field} is spread only when named`).to.include(
					`...(${field} !== undefined ? { ${field} } : {})`
				);
			}
		});

		// The dashboard hides its policy card when this call fails, so the
		// readback is the same object configure answers with.
		it('GET /direct-funding/config answers the shape configure returns', () => {
			const fields = [
				'lspPubkey',
				'lspHost',
				'lspPort',
				'targetInboundSat',
				'trusted',
				'minAmountSat'
			];
			expect(responseFields('/direct-funding/config', 'get')).to.have.members(
				fields
			);
			expect(responseFields('/direct-funding/configure')).to.have.members(
				fields
			);
		});

		// host and port are the CALLER's: the dashboard sends the browser's own
		// hostname and the manager sends PUBLIC_HOST, and the daemon cannot know
		// which is right, so it must not substitute its own.
		it('POST /direct-funding/request takes host, port and amountSats verbatim', () => {
			expect(requestParams('/direct-funding/request')).to.include.members([
				'host',
				'port',
				'amountSats'
			]);
			expect(responseFields('/direct-funding/request')).to.include.members([
				'paymentHash',
				'expiresAt',
				'request'
			]);
			const handler = handlerSource('POST /direct-funding/request', 900);
			expect(handler).to.include('...(dfHost !== undefined ? { host: dfHost }');
			expect(handler).to.include('...(dfPort !== undefined ? { port: dfPort }');
		});

		// feeHeadroomSats is what the app posts today; maxTotalFeeSat is the
		// documented name. Dropping the alias would silently uncap the fee.
		it('POST /direct-funding/send takes maxTotalFeeSat and the feeHeadroomSats alias', () => {
			expect(requestParams('/direct-funding/send')).to.include.members([
				'request',
				'amountSats',
				'maxTotalFeeSat',
				'feeHeadroomSats'
			]);
			const handler = handlerSource('POST /direct-funding/send', 900);
			expect(handler).to.include('feeHeadroomSats');
			expect(handler).to.include('maxTotalFeeSat');
		});

		// Deliberate, and recorded in src/lightning/README.md: third-party
		// witness injection is library-only. Over HTTP the same calls would let
		// anything holding an API token choose the inputs of this node's
		// funding transactions and co-sign them.
		it('no route accepts caller-built funding inputs or a witness', () => {
			for (const [method, route] of everyOperation()) {
				for (const banned of ['fundingUtxos', 'contribution', 'witness']) {
					expect(
						requestParams(route, method),
						`${method} ${route}`
					).to.not.include(banned);
				}
			}
			// The spec is documentation; the handlers are the surface. Both
			// destructure their body, so a parameter they never name is a
			// parameter they cannot forward.
			for (const routeKey of [
				'POST /channel/open-v2',
				'POST /channel/splice-in'
			]) {
				const handler = handlerSource(routeKey, 900);
				for (const banned of ['fundingUtxos', 'contribution', 'witness']) {
					expect(handler, `${routeKey} ${banned}`).to.not.include(banned);
				}
			}
		});
	});

	describe('response envelope', () => {
		// The app treats 2xx with ok !== false as success and reads `result`,
		// and anything else as a failure carrying error.code and error.message,
		// which it puts straight into a toast.
		it('answers with exactly two envelope shapes', () => {
			expect(daemonSrc).to.include('return { ok: true, result };');
			expect(daemonSrc).to.include(
				'return { ok: false, error: { code, message } };'
			);
		});

		it('lets a failure envelope drive the HTTP status', () => {
			expect(daemonSrc).to.include(
				'if (failureLike?.ok === false && failureLike.error?.code) {'
			);
		});

		// The third shape: a 200 whose `result` carries its own ok:false. The
		// app defends against it on splice-out ONLY, so a refusal on any other
		// route in this set reads to the app as a success. Growing this set is
		// therefore a decision rather than a detail.
		it('only the splice routes answer with an ok inside result', () => {
			const nested = everyOperation()
				.filter(([method, route]) =>
					responseFields(route, method).includes('ok')
				)
				.map(([method, route]) => `${method.toUpperCase()} ${route}`);
			expect(nested).to.have.members([
				'POST /channel/splice-in',
				'POST /channel/splice-out'
			]);
		});
	});

	describe('SSE events', () => {
		/** Bound by name in the dashboard; a rename stops the UI updating. */
		const DASHBOARD_EVENTS = [
			'payment:received',
			'payment:sent',
			'payment:failed',
			'invoice:settled',
			'transaction:received',
			'transaction:confirmed',
			'channel:ready',
			'channel:closed',
			'peer:connect',
			'peer:disconnect',
			'node:ready'
		];
		/** Additionally consumed by the app's daemon manager. */
		const MANAGER_EVENTS = [
			'channel:opening',
			'channel:pending-close',
			'channel:force-closing',
			'channel:closed',
			'channel:resolved',
			'node:error'
		];

		it('relays every event the app binds', () => {
			const relayed = getRelayedEvents();
			for (const e of [...DASHBOARD_EVENTS, ...MANAGER_EVENTS]) {
				expect(relayed, e).to.include(e);
			}
		});

		it('declares every relayed event in BeignetNodeEvents', () => {
			for (const e of getRelayedEvents(true)) {
				expect(typesSrc, e).to.include(`'${e}':`);
			}
		});

		it('documents every relayed event on GET /events', () => {
			const summary = String(spec.paths['/events'].get.summary);
			for (const e of getRelayedEvents(true)) {
				expect(summary, e).to.include(e);
			}
		});

		// The app's parser discards a frame with no name, and JSON.parses the
		// data line unconditionally.
		it('every frame carries a name and a JSON body', () => {
			const frame = formatSseFrame('channel:ready', { channelId: 'ab' });
			expect(frame.startsWith('event: channel:ready\n')).to.equal(true);
			expect(frame.endsWith('\n\n')).to.equal(true);
			expect(
				JSON.parse(frame.split('\n')[1].slice('data: '.length))
			).to.deep.equal({ channelId: 'ab' });
		});

		// node:ready is emitted with no payload at all. Interpolating
		// JSON.stringify(undefined) wrote the literal text `data: undefined`,
		// which throws in a client that parses every frame it is given.
		it('a payload-less event still carries parseable JSON', () => {
			expect(formatSseFrame('node:ready', undefined)).to.equal(
				'event: node:ready\ndata: {}\n\n'
			);
		});

		// The receive screen matches the hash on screen against the event.
		it('payment:received and invoice:settled carry the hash and the amount', () => {
			for (const shape of [
				declaration(typesSrc, 'export interface PaymentInfo {'),
				declaration(typesSrc, "'invoice:settled':", 200)
			]) {
				expect(shape).to.include('paymentHash');
				expect(shape).to.include('amountSats');
			}
		});

		it('transaction:received carries type, txid, valueSats and confirmed', () => {
			const shape = declaration(typesSrc, 'export interface OnchainTxInfo {');
			for (const field of ['txid', 'type', 'valueSats', 'confirmed']) {
				expect(shape, field).to.include(field);
			}
		});

		// The manager drops any channel entry without an id.
		it('every channel lifecycle event carries channelId', () => {
			for (const e of [
				'channel:opening',
				'channel:ready',
				'channel:pending-close',
				'channel:force-closing',
				'channel:closed',
				'channel:resolved'
			]) {
				expect(declaration(typesSrc, `'${e}':`, 200), e).to.include(
					'channelId'
				);
			}
		});

		// node:error is the only path by which an open failure reaches the app
		// at all, and channelId is what says which open it was.
		it('node:error carries code, message, channelId and timestamp', () => {
			const shape = declaration(typesSrc, "'node:error':", 700);
			for (const field of ['code', 'message', 'channelId', 'timestamp']) {
				expect(shape, field).to.include(field);
			}
			expect(beignetNodeSrc).to.include(
				"channelId: err.channelId ? err.channelId.toString('hex') : undefined"
			);
		});

		// Phase 4's jit:* events stop at the liquidity engine: nothing in the
		// daemon relays them and nothing in the app listens. Recorded so the
		// absence reads as a decision if someone goes looking for progress.
		it('relays no jit or direct-funding event', () => {
			for (const e of getRelayedEvents(true)) {
				expect(e.startsWith('jit:'), e).to.equal(false);
				expect(e.startsWith('df:'), e).to.equal(false);
			}
		});
	});

	describe('environment variables', () => {
		const VARS = [
			'BEIGNET_JIT_RECEIVE',
			'BEIGNET_JIT_FLAT_FEE_SAT',
			'BEIGNET_JIT_FEE_PPM',
			'BEIGNET_FEE_BASE_MSAT',
			'BEIGNET_FEE_PPM',
			'BEIGNET_CLTV_DELTA',
			'BEIGNET_LEASE_RATES',
			'BEIGNET_DF_RELAY',
			'BEIGNET_DF_MIN_AMOUNT',
			'BEIGNET_SWARM',
			'BEIGNET_TRUSTED_ZERO_CONF_SPLICE'
		];

		afterEach(() => {
			for (const v of VARS) delete process.env[v];
		});

		it('reads the names the app sets', () => {
			process.env.BEIGNET_JIT_RECEIVE = 'true';
			process.env.BEIGNET_JIT_FLAT_FEE_SAT = '250';
			process.env.BEIGNET_JIT_FEE_PPM = '1500';
			process.env.BEIGNET_FEE_BASE_MSAT = '1000';
			process.env.BEIGNET_FEE_PPM = '100';
			process.env.BEIGNET_CLTV_DELTA = '80';
			process.env.BEIGNET_DF_RELAY = 'true';
			process.env.BEIGNET_DF_MIN_AMOUNT = '25000';
			process.env.BEIGNET_LEASE_RATES = JSON.stringify({
				fundingWeightWitness: 666,
				leaseFeeBasis: 100,
				leaseFeeBaseSat: 500,
				channelFeeMaxBaseMsat: 5000,
				channelFeeMaxProportionalThousandths: 10
			});
			const config = resolveConfig({});
			expect(config.jitReceive).to.include({
				enabled: true,
				flatFeeSat: 250,
				feePpm: 1500
			});
			expect(config.routingFeeBaseMsat).to.equal(1000);
			expect(config.routingFeePpm).to.equal(100);
			expect(config.routingCltvDelta).to.equal(80);
			expect(config.dfRelay).to.equal(true);
			expect(config.dfMinAmountSat).to.equal(25_000);
			expect(config.leaseRates?.leaseFeeBaseSat).to.equal(500);
		});

		it('keeps a configured zero, which is a real policy', () => {
			process.env.BEIGNET_FEE_BASE_MSAT = '0';
			process.env.BEIGNET_FEE_PPM = '0';
			process.env.BEIGNET_JIT_FLAT_FEE_SAT = '0';
			const config = resolveConfig({});
			expect(config.routingFeeBaseMsat).to.equal(0);
			expect(config.routingFeePpm).to.equal(0);
			expect(config.jitReceive?.flatFeeSat).to.equal(0);
		});

		it('keeps an explicit false, which is a real policy', () => {
			process.env.BEIGNET_JIT_RECEIVE = 'false';
			expect(resolveConfig({}).jitReceive).to.include({ enabled: false });
		});

		// =1 must not read as an explicit false: an unrecognised value falls
		// back to the default, never to the opposite of what was written.
		it('a boolean that is not exactly true or false falls back, never flips', () => {
			for (const junk of ['1', 'TRUE', 'yes', 'on']) {
				process.env.BEIGNET_JIT_RECEIVE = junk;
				expect(resolveConfig({}).jitReceive?.enabled, junk).to.equal(undefined);
			}
		});

		// integerEnv: parseInt would read '10m' as 10 and advertise a policy
		// nobody wrote. NaN reaches the daemon's range check, which refuses
		// startup naming the variable.
		it('a partly numeric integer surfaces as NaN rather than a truncation', () => {
			for (const junk of ['10m', '0.5', '1 000']) {
				process.env.BEIGNET_FEE_BASE_MSAT = junk;
				expect(
					Number.isNaN(resolveConfig({}).routingFeeBaseMsat),
					junk
				).to.equal(true);
			}
		});

		// Two keys the app sets that we deliberately do not implement.
		// BEIGNET_TRUSTED_ZERO_CONF_SPLICE: upstream locks zero-conf splices at
		// tx_signatures. BEIGNET_SWARM belongs to #533. Both are unknown
		// variables, ignored in silence, with no compat shim.
		it('ignores the two keys the app sets that we do not implement', () => {
			const before = JSON.stringify(resolveConfig({}));
			process.env.BEIGNET_SWARM = 'true';
			process.env.BEIGNET_TRUSTED_ZERO_CONF_SPLICE = 'true';
			expect(JSON.stringify(resolveConfig({}))).to.equal(before);
			for (const [name, src] of [
				['config.ts', read('cli/config.ts')],
				['daemon.ts', daemonSrc],
				['cli.ts', read('cli/cli.ts')],
				['beignet-node.ts', beignetNodeSrc]
			] as const) {
				expect(src, name).to.not.include('BEIGNET_SWARM');
				expect(src, name).to.not.include('BEIGNET_TRUSTED_ZERO_CONF_SPLICE');
			}
		});

		it('never loads hyperswarm', () => {
			const pkg = JSON.parse(
				fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf8')
			) as { dependencies: Record<string, string> };
			expect(Object.keys(pkg.dependencies)).to.not.include('hyperswarm');
			// The transport registry is a plugin table precisely so an optional
			// lane is never imported at boot (#611).
			// eslint-disable-next-line @typescript-eslint/no-var-requires
			require('../../src/lightning/direct-funding');
			expect(
				Object.keys(require.cache).some((k) => k.includes('hyperswarm'))
			).to.equal(false);
		});
	});

	/**
	 * The dashboard's own decode, run over an envelope a live daemon just
	 * minted. #614 asks for this row end to end rather than against a fixture:
	 * 4A pins the offsets against a constructed envelope, and this says the
	 * daemon's minting path puts the same bytes in the same places.
	 *
	 * The decoder is hard coded to those offsets and FAILS OPEN. A field that
	 * moves does not raise in the app, it shows a different node id, a
	 * different expiry or a different amount, so the wrong number reaches the
	 * person deciding whether to pay.
	 */
	describe('minted envelope, against a live daemon', function () {
		this.timeout(30_000);
		let dataDir: string;
		let daemon: Awaited<ReturnType<typeof startDaemon>>;
		let port: number;

		const call = (
			route: string,
			body?: unknown
		): Promise<Record<string, unknown>> =>
			new Promise((resolve, reject) => {
				const req = http.request(
					{
						host: '127.0.0.1',
						port,
						path: route,
						method: body === undefined ? 'GET' : 'POST',
						headers: { 'content-type': 'application/json' }
					},
					(res) => {
						let raw = '';
						res.on('data', (c) => (raw += c));
						res.on('end', () =>
							resolve(JSON.parse(raw) as Record<string, unknown>)
						);
					}
				);
				req.on('error', reject);
				req.end(body === undefined ? undefined : JSON.stringify(body));
			});

		before(async () => {
			dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-5a-'));
			daemon = await startDaemon({
				dataDir,
				// No reachable Electrum: minting a request is local work, and a
				// daemon that never syncs starts faster than one that does.
				electrumHost: '127.0.0.1',
				electrumPort: 65529,
				electrumTls: false,
				rapidGossipSync: false,
				autoGossipSync: false,
				logLevel: 'silent',
				network: 'regtest',
				mnemonic:
					'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
				daemonPort: 0
			});
			port = (daemon.server.address() as AddressInfo).port;
		});

		after(async () => {
			await daemon.stop();
			fs.rmSync(dataDir, { recursive: true, force: true });
		});

		it('decodes at the offsets the dashboard reads', async () => {
			const info = (await call('/info')).result as { nodeId: string };
			const minted = (
				await call('/direct-funding/request', {
					host: '10.0.0.5',
					port: 9736,
					amountSats: 250_000
				})
			).result as { request: string; expiresAt: number };

			// The dashboard's gate: unpadded base64url, or it does not decode at
			// all. A '=' survives a BIP 21 round trip percent-encoded and would
			// fail the regex on the far side.
			expect(minted.request).to.match(/^[A-Za-z0-9_-]+$/);

			const bytes = Buffer.from(minted.request, 'base64url');
			expect(bytes.subarray(49, 82).toString('hex')).to.equal(info.nodeId);
			expect(bytes.readUIntBE(82, 6)).to.equal(minted.expiresAt);
			// Byte 88 is the flags bit that says an amount follows at 89.
			expect(bytes[88] & 1).to.equal(1);
			expect(bytes.readBigUInt64BE(89)).to.equal(250_000n);
		});
	});

	describe('library surface', () => {
		// Added by 4C as the twin of getPendingSpliceTx, and the pair is the
		// only way an out-of-process input owner learns what to sign.
		it('exports both pending-transaction accessors on both classes', () => {
			for (const name of ['getPendingSpliceTx', 'getPendingV2FundingTx']) {
				expect(
					typeof (Channel.prototype as unknown as Record<string, unknown>)[
						name
					],
					`Channel.${name}`
				).to.equal('function');
				expect(
					typeof (
						LightningNode.prototype as unknown as Record<string, unknown>
					)[name],
					`LightningNode.${name}`
				).to.equal('function');
			}
		});

		it('exports the rest of the third-party funding family', () => {
			for (const name of [
				'provideV2ExternalWitness',
				'provideSpliceExternalWitness',
				'getRawChannel',
				'spliceInWithInputs'
			]) {
				expect(
					typeof (
						LightningNode.prototype as unknown as Record<string, unknown>
					)[name],
					name
				).to.equal('function');
			}
		});

		it('records the absence of a daemon surface for it', () => {
			const readme = fs.readFileSync(
				path.join(SRC, 'lightning/README.md'),
				'utf8'
			);
			expect(readme).to.include('Third-party funding inputs (library only)');
			expect(readme).to.include('provideSpliceExternalWitness');
		});
	});
});
