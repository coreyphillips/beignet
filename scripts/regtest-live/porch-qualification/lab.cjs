'use strict';
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const exec = promisify(execFile);
const base = __dirname;
const names = {
	primary: 'beignet-porch-primary',
	phone: 'beignet-porch-phone',
	relay: 'beignet-porch-relay',
	tor: 'beignet-porch-tor',
	caddy: 'beignet-porch-caddy'
};
/** The two Lightning endpoints; the others have no control server. */
const endpoints = ['primary', 'phone'];
const routes = ['tcp', 'porch', 'porch-tls', 'porch-tor'];
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function docker(...args) {
	return (
		await exec('docker', args, {
			encoding: 'utf8',
			timeout: 125000,
			maxBuffer: 8 * 1024 * 1024
		})
	).stdout.trim();
}
async function rpc(role, op, body = {}) {
	const result = JSON.parse(
		await docker(
			'exec',
			names[role],
			'node',
			'/fixture/rpc.cjs',
			JSON.stringify({ op, body })
		)
	);
	assert.equal(result.ok, true, JSON.stringify(result));
	return result.value;
}
async function btc(...args) {
	return docker(
		'exec',
		process.env.BEIGNET_REGTEST_BITCOIN || 'bitcoin',
		'bitcoin-cli',
		'-rpcport=43782',
		'-rpcuser=polaruser',
		'-rpcpassword=polarpass',
		'-rpcwallet=default',
		...args
	);
}
async function wait(label, read, timeout = 120000, interval = 400) {
	const started = Date.now();
	let last;
	while (Date.now() - started < timeout) {
		last = await read();
		if (last) return last;
		await delay(interval);
	}
	throw Error(label + ' timed out after ' + timeout + 'ms');
}
function record(kind, value) {
	const row = { at: new Date().toISOString(), kind, ...value };
	fs.appendFileSync(
		path.join(base, 'results.jsonl'),
		JSON.stringify(row) + '\n'
	);
	console.log(JSON.stringify(row));
	return row;
}
async function statuses() {
	return Object.fromEntries(
		await Promise.all(
			endpoints.map(async (role) => [role, await rpc(role, 'status')])
		)
	);
}
const failures = (state) =>
	state.events.filter((e) =>
		['channel:errored', 'channel:closed', 'channel:voided'].includes(e.name)
	);
async function healthy(expectedIds) {
	const states = await statuses();
	for (const [role, state] of Object.entries(states)) {
		assert.equal(state.info.network, 'regtest');
		assert.equal(state.channels.length, 1);
		const c = state.channels[0];
		assert.equal(c.channelId, expectedIds[role]);
		assert.equal(c.state, 'NORMAL', JSON.stringify(c));
		assert.equal(c.htlcUsable, true);
		assert.equal(c.htlcCount, 0);
		assert.equal(failures(state).length, 0, JSON.stringify(failures(state)));
	}
	assert.equal(
		states.primary.channels[0].localBalanceSats,
		states.phone.channels[0].remoteBalanceSats
	);
	assert.equal(
		states.phone.channels[0].localBalanceSats,
		states.primary.channels[0].remoteBalanceSats
	);
	assert.equal(
		states.primary.channels[0].localBalanceSats +
			states.phone.channels[0].localBalanceSats,
		1000000
	);
	return states;
}
async function settled(ids, timeout = 120000) {
	return wait(
		'original channel settled on both ends',
		async () => {
			// An endpoint that is restarting does not answer yet.
			const s = await statuses().catch(() => undefined);
			if (!s) return false;
			for (const [role, state] of Object.entries(s)) {
				assert.equal(
					failures(state).length,
					0,
					JSON.stringify(failures(state))
				);
				assert.equal(state.channels.length, 1);
				assert.equal(state.channels[0].channelId, ids[role]);
			}
			return Object.values(s).every(
				(endpoint) =>
					endpoint.channels[0].htlcUsable &&
					endpoint.channels[0].htlcCount === 0
			)
				? s
				: false;
		},
		timeout
	);
}
async function pay(from, to, options = {}) {
	const invoice = await rpc(to, 'invoice', { amount: options.amount || 1000 });
	const started = Date.now();
	const { id } = await rpc(from, 'pay', { bolt11: invoice.bolt11 });
	const job = await wait(
		'payment result',
		async () => {
			const j = await rpc(from, 'job', { id });
			return j.done ? j : false;
		},
		120000,
		options.interval || 400
	);
	const received = await rpc(to, 'invoice-status', {
		hash: invoice.paymentHash
	});
	const payment = await rpc(from, 'payment-status', {
		hash: invoice.paymentHash
	});
	return {
		from,
		to,
		elapsedMs: Date.now() - started,
		hash: invoice.paymentHash,
		job,
		received,
		payment
	};
}
/**
 * The link the phone dials on a path, from what the primary reports.
 *
 * On porch-tor the primary hands out the relay's onion name, because that is
 * the name it knows the relay by here. The phone uses no Tor, so the fixture
 * gives it the same link at the relay's name on the fixture network. A route
 * id does not depend on the relay's name, and the relay answers to both.
 */
function link(route, primary) {
	assert.equal(primary.route, route);
	if (route === 'tcp') return primary.info.nodeId + '@primary:9735';
	const uri = primary.info.porch?.uris[0];
	if (!uri) return undefined;
	if (route !== 'porch-tor') return uri;
	assert.match(uri, /@ws:\/\/[a-z2-7]{56}\.onion:2114\/v1\/p\//);
	return uri.replace(/@ws:\/\/[a-z2-7]{56}\.onion:2114\//, '@ws://relay:2114/');
}
/** What each end reports its peer was connected by, on a path. */
const expected = (route) =>
	route === 'tcp'
		? { primary: 'tcp', phone: 'tcp' }
		: { primary: 'porch', phone: 'ws' };
// The daemon names the transport of a WebSocket or Iroh peer and leaves a
// plain TCP one unnamed.
const via = (peer) => (peer.porch ? 'porch' : peer.transport ?? 'tcp');
/** The host and port a link is dialed at, as the dialer then lists its peer. */
function target(uri) {
	const address = uri.slice(uri.indexOf('@') + 1);
	if (/^wss?:\/\//.test(address)) {
		const url = new URL(address);
		return {
			host: url.hostname,
			port: Number(url.port) || (url.protocol === 'wss:' ? 443 : 80)
		};
	}
	const colon = address.lastIndexOf(':');
	return {
		host: address.slice(0, colon),
		port: Number(address.slice(colon + 1))
	};
}
module.exports = {
	base,
	names,
	endpoints,
	routes,
	delay,
	docker,
	rpc,
	btc,
	wait,
	record,
	statuses,
	failures,
	healthy,
	settled,
	pay,
	link,
	expected,
	via,
	target,
	assert,
	fs,
	path
};
