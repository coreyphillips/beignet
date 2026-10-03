'use strict';
// Disposable regtest endpoint. The control server is container-loopback only.
const http = require('node:http');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const root = '/opt/beignet/node_modules/beignet';
const { BeignetNode } = require(root + '/dist/cli/beignet-node.js');
const { parsePeerUri } = require(root +
	'/dist/lightning/transport/peer-uri.js');
const version = require(root + '/package.json').version;
assert.equal(version, '0.26.0');
const events = [],
	jobs = new Map();
let node,
	serial = 0;
const json = (value) =>
	JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
const event = (name, detail) => {
	const row = { at: Date.now(), name, detail };
	events.push(row);
	console.log(json(row));
};
async function request(op, body) {
	switch (op) {
		case 'status':
			return {
				version,
				info: node.getInfo(),
				health: node.getHealth(),
				peers: node.listPeers(),
				channels: node.listChannels(),
				events
			};
		case 'address':
			return node.getNewAddress();
		case 'refresh':
			await node.refreshWallet();
			return node.getBalance();
		case 'connect': {
			const p = parsePeerUri(body.uri);
			assert.equal(p.transport.type, 'iroh');
			await node.connectPeer(p.pubkey, p.host, p.port, p.transport);
			return node.listPeers();
		}
		case 'trust':
			node.addTrustedPeer(body.peer);
			return true;
		case 'open':
			return node.openChannel(body.peer, 1000000, 0, 2, false, true);
		case 'invoice':
			return node.createInvoice(
				body.amount || 1000,
				'Disposable Iroh qualification',
				3600
			);
		case 'invoice-status':
			return node.getInvoice(body.hash);
		case 'payment-status':
			return node.getPayment(body.hash);
		case 'pay': {
			const id = ++serial;
			const job = {
				id,
				started: Date.now(),
				done: false,
				cutDecided: body.cutAfterMs === undefined
			};
			jobs.set(id, job);
			node.payInvoiceSafe(body.bolt11, 90000, 100).then(
				(result) => {
					job.result = result;
					job.done = true;
					job.finished = Date.now();
				},
				(error) => {
					job.error = { message: error.message, code: error.code };
					job.done = true;
					job.finished = Date.now();
				}
			);
			if (body.cutAfterMs !== undefined)
				setTimeout(() => {
					const payment = node.getPayment(body.hash);
					const channel = node
						.listChannels()
						.find((c) => c.peerPubkey === body.peer);
					const peer = node.node.peerManager.getPeer(body.peer);
					job.observed = {
						status: payment?.status,
						htlcs: channel?.htlcCount,
						peerState: peer?.getState()
					};
					// Interrupt only an actual in-flight HTLC. Touch the transport only;
					// never modify channel state, signed messages or persistence.
					if (
						!job.done &&
						channel?.htlcCount > 0 &&
						peer?.socket?.transportType === 'iroh'
					) {
						job.cutAt = Date.now();
						peer.socket.destroy();
						event('in-flight-cut', {
							id,
							delayMs: job.cutAt - job.started,
							...job.observed
						});
					}
					job.cutDecided = true;
				}, body.cutAfterMs);
			return { id };
		}
		case 'job':
			return jobs.get(body.id);
		default:
			throw Error('Unknown fixture operation');
	}
}
(async () => {
	const seedFile = '/data/disposable-regtest-seed';
	node = await BeignetNode.create({
		mnemonic: fs.existsSync(seedFile)
			? fs.readFileSync(seedFile, 'utf8')
			: undefined,
		network: 'regtest',
		dataDir: '/data',
		allowMultipleInstances: true,
		electrumHost: 'host.docker.internal',
		electrumPort: 60001,
		electrumTls: false,
		iroh: true,
		irohDiscovery: false,
		autoBootstrap: false,
		autoGossipSync: false,
		autoReconnect: true,
		forwardingEnabled: true,
		logger: {
			debug() {
				/* Keep low-level logs out of the qualification output. */
			},
			info() {
				/* Structured fixture events provide progress. */
			},
			warn(message, details) {
				event('warning', { message, details });
			},
			error(message, details) {
				event('error', { message, details });
			}
		}
	});
	assert.equal(node.getInfo().network, 'regtest');
	if (!fs.existsSync(seedFile))
		fs.writeFileSync(seedFile, node.getMnemonic(), { mode: 0o600, flag: 'wx' });
	node.node
		.getChannelManager()
		.on('channel:errored', (channelId, reason) =>
			event('channel:errored', { channelId: channelId.toString('hex'), reason })
		);
	for (const name of [
		'channel:closed',
		'channel:voided',
		'peer:connect',
		'peer:disconnect',
		'peer:error'
	])
		node.on(name, (value) => event(name, value));
	const server = http.createServer(async (req, res) => {
		try {
			let raw = '';
			for await (const chunk of req) {
				raw += chunk;
				if (raw.length > 100000) throw Error('Oversized request');
			}
			const { op, body = {} } = JSON.parse(raw);
			const value = await request(op, body);
			res.end(json({ ok: true, value }));
		} catch (error) {
			res.end(json({ ok: false, error: error.message, code: error.code }));
		}
	});
	server.listen(8089, '127.0.0.1', () =>
		event('ready', { version, network: 'regtest' })
	);
	process.on('SIGTERM', async () => {
		server.close();
		await node.gracefulShutdown(5000);
		process.exit(0);
	});
})().catch((error) => {
	console.error(error);
	process.exit(1);
});
