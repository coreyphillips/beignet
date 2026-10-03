'use strict';
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const exec = promisify(execFile);
const base = __dirname;
const names = { primary: 'beignet-iroh-primary', phone: 'beignet-iroh-phone' };
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
			Object.keys(names).map(async (role) => [role, await rpc(role, 'status')])
		)
	);
}
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
		const failures = state.events.filter((e) =>
			['channel:errored', 'channel:closed', 'channel:voided'].includes(e.name)
		);
		assert.equal(failures.length, 0, JSON.stringify(failures));
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
			const s = await statuses();
			for (const [role, state] of Object.entries(s)) {
				const failures = state.events.filter((e) =>
					['channel:errored', 'channel:closed', 'channel:voided'].includes(
						e.name
					)
				);
				assert.equal(failures.length, 0, JSON.stringify(failures));
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
	const peer = (await rpc(to, 'status')).info.nodeId;
	const target = {
		bolt11: invoice.bolt11,
		hash: invoice.paymentHash,
		peer,
		cutAfterMs: options.cutAfterMs
	};
	let id, warmupFinished, warmupHash;
	if (options.cutAfterMs === undefined)
		({ id } = await rpc(from, 'pay', target));
	else {
		const warmup = await rpc(to, 'invoice', { amount: 1000 });
		warmupHash = warmup.paymentHash;
		({ id, warmupFinished } = JSON.parse(
			await docker(
				'exec',
				names[from],
				'node',
				'/fixture/burst.cjs',
				JSON.stringify({ warmupBolt11: warmup.bolt11, target })
			)
		));
	}
	let reconnect;
	if (options.cutAfterMs !== undefined) {
		const job = await wait('cut decision', async () => {
			const j = await rpc(from, 'job', { id });
			return j.cutDecided ? j : false;
		});
		if (job.cutAt && options.reconnect) {
			// Stress runs explicitly redial to separate channel safety from the
			// production reconnect backoff. Outage runs never use this path.
			await delay(1500);
			try {
				reconnect = await rpc('phone', 'connect', { uri: options.reconnect });
			} catch (error) {
				record('stress-redial-error', { message: error.message });
			}
		}
	}
	const job = await wait(
		'payment result',
		async () => {
			const j = await rpc(from, 'job', { id });
			return j.done && j.cutDecided ? j : false;
		},
		120000
	);
	const received = await rpc(to, 'invoice-status', {
		hash: invoice.paymentHash
	});
	const payment = await rpc(from, 'payment-status', {
		hash: invoice.paymentHash
	});
	const warmupInvoiceStatus = warmupHash
		? (await rpc(to, 'invoice-status', { hash: warmupHash }))?.status
		: undefined;
	return {
		from,
		to,
		elapsedMs: Date.now() - started,
		hash: invoice.paymentHash,
		job,
		received,
		payment,
		explicitRedial: !!reconnect,
		warmupGapMs: warmupFinished ? job.started - warmupFinished : undefined,
		warmupInvoiceStatus
	};
}
module.exports = {
	base,
	names,
	delay,
	docker,
	rpc,
	btc,
	wait,
	record,
	statuses,
	healthy,
	settled,
	pay,
	assert,
	fs,
	path
};
