'use strict';
// Disposable regtest endpoint. The control server is container-loopback only.
const started = Date.now();
const net = require('node:net');
// Every outbound TCP connection this process makes, by destination as the
// caller gave it, recorded from before the engine is loaded. Accepted sockets
// never call connect(), so this is exactly what the process dialed.
const dialed = {};
const noDelay = process.env.QUALIFY_TCP_NODELAY === 'true';
{
	const original = net.Socket.prototype.connect;
	net.Socket.prototype.connect = function (...args) {
		// net.connect() normalises its arguments into one array before it
		// calls this; a direct socket.connect(port, host) does not.
		const first = Array.isArray(args[0]) ? args[0][0] : args[0];
		const where =
			first !== null && typeof first === 'object'
				? first.path || (first.host || 'localhost') + ':' + first.port
				: (typeof args[1] === 'string' ? args[1] : 'localhost') + ':' + first;
		dialed[where] = (dialed[where] || 0) + 1;
		if (noDelay) this.setNoDelay(true);
		return original.apply(this, args);
	};
	// QUALIFY_TCP_NODELAY=true: send every segment at once on the sockets
	// this process dials and on the ones its Lightning listener accepts, as
	// the WebSocket transports already do. For telling what Nagle's algorithm
	// costs the plain TCP path apart from what the path itself costs.
	const createServer = net.createServer;
	if (noDelay)
		net.createServer = function (...args) {
			return createServer
				.apply(this, args)
				.on('connection', (socket) => socket.setNoDelay(true));
		};
}
const http = require('node:http');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const root = '/opt/beignet/node_modules/beignet';
const { BeignetNode } = require(root + '/dist/cli/beignet-node.js');
const { parsePeerUri } = require(root +
	'/dist/lightning/transport/peer-uri.js');
const version = require(root + '/package.json').version;
const role = process.env.QUALIFY_ROLE;
assert.ok(['primary', 'phone'].includes(role));
// How the primary can be reached. The phone is the same on every path: it
// dials whatever link it is handed, as anyone holding one would.
const route = role === 'primary' ? process.env.QUALIFY_PATH : undefined;
function reachable() {
	if (role !== 'primary') return {};
	assert.ok(['tcp', 'porch', 'porch-tls', 'porch-tor'].includes(route));
	if (route === 'tcp') return { listenPort: 9735 };
	if (route === 'porch') return { porchRelays: ['ws://relay:2114'] };
	// The relay behind the TLS terminator, as a hosted one is.
	if (route === 'porch-tls') return { porchRelays: ['wss://relay.test'] };
	// The relay as Tor reaches it in this fixture: its onion service.
	const onion = fs.readFileSync('/onion/relay/hostname', 'utf8').trim();
	return {
		porchRelays: ['ws://' + onion + ':2114'],
		porchVia: 'tor',
		torProxy: 'tor:9050'
	};
}
const events = [],
	jobs = new Map();
// What each peer was connected by, sampled every 100 ms since start. The
// daemon leaves a plain TCP peer's transport unnamed.
const pathSamples = { tcp: 0, ws: 0, porch: 0 };
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
				role,
				route,
				noDelay,
				started,
				info: node.getInfo(),
				health: node.getHealth(),
				peers: node.listPeers(),
				channels: node.listChannels(),
				pathSamples: { ...pathSamples },
				dialed: { ...dialed },
				events
			};
		case 'address':
			return node.getNewAddress();
		case 'refresh':
			await node.refreshWallet();
			return node.getBalance();
		case 'connect': {
			const p = parsePeerUri(body.uri);
			assert.ok(!p.transport || p.transport.type === 'ws');
			await node.connectPeer(p.pubkey, p.host, p.port, p.transport);
			return node.listPeers();
		}
		case 'disconnect':
			node.disconnectPeer(body.peer);
			return true;
		case 'trust':
			node.addTrustedPeer(body.peer);
			return true;
		case 'open':
			return node.openChannel(body.peer, 1000000, 0, 2, false, true);
		case 'invoice':
			return node.createInvoice(
				body.amount || 1000,
				'Disposable Porch qualification',
				3600
			);
		case 'invoice-status':
			return node.getInvoice(body.hash);
		case 'payment-status':
			return node.getPayment(body.hash);
		case 'pay': {
			const id = ++serial;
			const job = { id, started: Date.now(), done: false };
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
		...reachable(),
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
	setInterval(() => {
		for (const peer of node.listPeers())
			pathSamples[peer.porch ? 'porch' : peer.transport ?? 'tcp']++;
	}, 100).unref();
	// When the channel became usable and when it stopped being, to 25 ms,
	// which the harness cannot see through a docker exec round trip.
	let usable = false;
	setInterval(() => {
		const now = node.listChannels().some((c) => c.htlcUsable);
		if (now === usable) return;
		usable = now;
		event(now ? 'usable' : 'unusable', { sinceStartMs: Date.now() - started });
	}, 25).unref();
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
		event('ready', { version, role, route, noDelay, network: 'regtest' })
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
