/**
 * Two daemons whose nodes talk over a loopback, and everything each of them
 * relays: its SSE stream as a client reads it and the bodies its webhooks
 * deliver.
 *
 * `ordinaryFlow` opens an ordinary channel between the two and sends a
 * payment each way, one that is held and settled and one that is held and
 * failed back. `normalise` writes what such a run streamed without the
 * values that differ from run to run, so that two runs can be compared
 * byte for byte. Nothing here names an asset channel: the same file runs
 * on a build from before them, which is how the pinned streams were
 * printed.
 */

import { createHash } from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import { AddressInfo } from 'net';
import * as os from 'os';
import * as path from 'path';
import { IStartedDaemon, startDaemon } from '../../../src/cli/daemon';
import type { LightningNode } from '../../../src/lightning/node/lightning-node';
import {
	connectNodes,
	openReadyChannel
} from '../../lightning/helpers/loopback-nodes';

export const STREAM_MNEMONICS = [
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
	'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'
];

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

/** The events a wallet draws its payments, invoices, holds and channels from. */
const STREAMED = /^(payment:|invoice:settled$|hold:|channel:)/;

/** One relayed event: its name and its data as the bytes that were sent. */
export type TFrame = [event: string, data: string];

export interface IStreamDaemon {
	daemon: IStartedDaemon;
	node: LightningNode;
	port: number;
	/** The frames of GET /events, in the order they came. */
	sse: TFrame[];
	/** The bodies the webhook was sent, in the order they arrived. */
	hooks: TFrame[];
	close: () => Promise<void>;
}

const sha = (data: Buffer | string): Buffer =>
	createHash('sha256').update(data).digest();

/** Let queued work run: `rounds` turns of the event loop. */
export async function streamTurns(rounds = 200): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

function post(
	port: number,
	urlPath: string,
	body: Record<string, unknown>
): Promise<number> {
	return new Promise((resolve, reject) => {
		const payload = JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: urlPath,
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(payload)
				}
			},
			(res) => {
				res.resume();
				res.on('end', () => resolve(res.statusCode ?? 0));
			}
		);
		req.on('error', reject);
		req.end(payload);
	});
}

/**
 * Start a daemon on a fresh data directory, read its SSE stream and
 * register a webhook for every event with a recipient that keeps what it
 * is sent.
 */
export async function bootStreamDaemon(
	tag: string,
	mnemonic: string,
	options: Record<string, unknown> = {}
): Promise<IStreamDaemon> {
	const dataDir = fs.mkdtempSync(
		path.join(os.tmpdir(), `beignet-event-stream-${tag}-`)
	);
	const daemon = await startDaemon({
		...OFFLINE,
		dataDir,
		mnemonic,
		...options
	});
	const port = (daemon.server.address() as AddressInfo).port;
	const sse: TFrame[] = [];
	const hooks: TFrame[] = [];

	const stream = await new Promise<http.ClientRequest>((resolve, reject) => {
		const req = http.get(
			{ hostname: '127.0.0.1', port, path: '/events' },
			(res) => {
				let buffer = '';
				res.setEncoding('utf8');
				res.on('data', (chunk: string) => {
					buffer += chunk;
					for (;;) {
						const end = buffer.indexOf('\n\n');
						if (end < 0) break;
						const frame = buffer.slice(0, end);
						buffer = buffer.slice(end + 2);
						const match = /^event: (.+)\ndata: (.*)$/s.exec(frame);
						if (match && STREAMED.test(match[1])) {
							sse.push([match[1], match[2]]);
						}
					}
				});
				res.on('error', () => undefined);
				resolve(req);
			}
		);
		req.on('error', reject);
	});

	const recipient = http.createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on('data', (chunk: Buffer) => chunks.push(chunk));
		req.on('end', () => {
			const text = Buffer.concat(chunks).toString();
			const body = JSON.parse(text) as { event: string };
			if (STREAMED.test(body.event)) {
				// The data as it was sent, cut out of the body: the bytes
				// between `"data":` and the timestamp that ends it.
				const from = text.indexOf('"data":') + '"data":'.length;
				const to = text.lastIndexOf(',"timestamp":');
				hooks.push([body.event, text.slice(from, to)]);
			}
			res.writeHead(200);
			res.end();
		});
	});
	await new Promise<void>((resolve) =>
		recipient.listen(0, '127.0.0.1', () => resolve())
	);
	const status = await post(port, '/webhooks/register', {
		url: `http://127.0.0.1:${(recipient.address() as AddressInfo).port}/hook`,
		events: ['*'],
		allowPrivateNetwork: true
	});
	if (status !== 200) throw new Error(`webhook not registered: ${status}`);

	const node = daemon.node.getNode();
	node.on('node:error', () => undefined);
	// The node is taken off its transport for the run: with no peer manager
	// it hands every message to 'message:outbound', as the loopback nodes of
	// the engine tests do, and two daemons are joined without a socket.
	const wired = node as unknown as {
		peerManager: unknown;
		channelManager: { peerManager: unknown };
	};
	const transport = [wired.peerManager, wired.channelManager.peerManager];
	wired.peerManager = null;
	wired.channelManager.peerManager = null;
	// A daemon opens no channel before it knows the chain tip, and this one
	// has no chain to ask.
	node.handleNewBlock(1);
	return {
		daemon,
		node,
		port,
		sse,
		hooks,
		close: async (): Promise<void> => {
			stream.destroy();
			[wired.peerManager, wired.channelManager.peerManager] = transport;
			try {
				await daemon.stop();
			} catch {
				// Already stopped.
			}
			await new Promise<void>((resolve) => recipient.close(() => resolve()));
			fs.rmSync(dataDir, { recursive: true, force: true });
		}
	};
}

/** Join the two daemons' nodes, as peers that are connected. */
export function joinStreamDaemons(a: IStreamDaemon, b: IStreamDaemon): void {
	connectNodes(a.node, b.node);
}

/**
 * Wait until every webhook body of the events each daemon streamed has
 * arrived, and until nothing more comes.
 */
export async function streamsDrained(
	daemons: IStreamDaemon[],
	timeoutMs = 20_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	let quiet = 0;
	let last = -1;
	for (;;) {
		await streamTurns(50);
		await new Promise((resolve) => setTimeout(resolve, 50));
		const level = daemons.every((d) => d.hooks.length === d.sse.length);
		const total = daemons.reduce((sum, d) => sum + d.sse.length, 0);
		quiet = level && total === last ? quiet + 1 : 0;
		last = total;
		if (quiet >= 4) return;
		if (Date.now() > deadline) {
			throw new Error(
				`streams did not drain: ${daemons
					.map((d) => `${d.sse.length} frames, ${d.hooks.length} bodies`)
					.join('; ')}`
			);
		}
	}
}

/**
 * The frames without what differs between two runs: a hex string of 32
 * bytes or more and a short channel id are numbered by their first
 * appearance, an invoice is `<bolt11>`, and a clock reading is `<time>`.
 */
export function normalise(frames: ReadonlyArray<Readonly<TFrame>>): string[] {
	const seen = new Map<string, string>();
	return frames.map(
		([event, data]) =>
			`${event} ${data
				.replace(/"ln(?:bcrt|bc|tbs|tb)[0-9a-z]+"/g, '"<bolt11>"')
				.replace(
					/[0-9a-f]{64,}|(?<="shortChannelId":")[0-9a-f]{16}(?=")/g,
					(value) => {
						let name = seen.get(value);
						if (!name) {
							name = `<hex${seen.size + 1}>`;
							seen.set(value, name);
						}
						return name;
					}
				)
				.replace(/\b1[6-9][0-9]{8}(?:[0-9]{3})?\b/g, '<time>')}`
	);
}

/** A frame's data as a webhook sends it: without the preimage. */
export function asWebhookSends(frame: Readonly<TFrame>): TFrame {
	const data = JSON.parse(frame[1]) as Record<string, unknown>;
	if (data && typeof data === 'object' && 'preimage' in data) {
		delete data.preimage;
	}
	return [frame[0], JSON.stringify(data)];
}

/**
 * An ordinary channel from `a` to `b`, a payment each way, a payment `b`
 * holds and settles, and one it holds and fails back. `label` keeps the
 * hashes of two flows on the same wallets apart.
 */
export async function ordinaryFlow(
	a: IStreamDaemon,
	b: IStreamDaemon,
	label = 'ordinary'
): Promise<Buffer> {
	const channelId = openReadyChannel(a.node, b.node);
	await streamTurns();

	const first = b.node.createInvoice({
		amountMsat: 20_000_000n,
		description: `${label} there`
	});
	a.node.sendPayment(first.bolt11);
	await streamTurns();

	const second = a.node.createInvoice({
		amountMsat: 7_000_000n,
		description: `${label} back`
	});
	b.node.sendPayment(second.bolt11);
	await streamTurns();

	const preimage = sha(`${label} held and settled`);
	const held = b.node.createInvoice({
		amountMsat: 5_000_000n,
		description: `${label} held`,
		hold: true,
		paymentHash: sha(preimage)
	});
	a.node.sendPayment(held.bolt11);
	await streamTurns();
	b.node.settleHeldHtlc(sha(preimage), preimage);
	await streamTurns();

	const refused = sha(sha(`${label} held and failed back`));
	const failed = b.node.createInvoice({
		amountMsat: 3_000_000n,
		description: `${label} failed back`,
		hold: true,
		paymentHash: refused
	});
	a.node.sendPayment(failed.bolt11);
	await streamTurns();
	b.node.cancelHoldInvoice(refused);
	await streamTurns();
	return channelId;
}
