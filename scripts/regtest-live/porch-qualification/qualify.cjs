'use strict';
const {
	base,
	names,
	endpoints,
	routes,
	delay,
	docker,
	rpc,
	wait,
	record,
	statuses,
	failures,
	healthy,
	settled,
	pay,
	target,
	assert,
	fs,
	path
} = require('./lab.cjs');
const os = require('node:os');
const network = require('./network.cjs');
const { dial, selected } = require('./route.cjs');
const { ids } = JSON.parse(fs.readFileSync(path.join(base, 'channel.json')));
const route = process.argv[2];
const phase = process.argv[3] || 'all';
assert.ok(routes.includes(route));
assert.ok(['all', 'baseline', 'latency', 'restart', 'outages'].includes(phase));
// On the TCP path nothing is hidden: it is the control for the checks below
// and the floor for the numbers.
const porch = route !== 'tcp';
// For trying the fixture out: fewer rounds of each restart, and a shorter
// wait between scenarios than the engine's reconnect backoff needs to reset.
const rounds = Number(process.env.QUALIFY_ROUNDS || 3);
const cooldownMs = Number(process.env.QUALIFY_COOLDOWN_MS || 61000);
// The chain source, the same on every path. The engine resolves its name
// first, so it is known here by its port.
const electrum = (where) => where.endsWith(':60001');
const zero = { out: 0, in: 0 };
// What else the machine was doing: its load average over the last minute.
// Payment times move with it, on every path alike.
const hostLoad = () => Math.round(os.loadavg()[0] * 10) / 10;
const brief = (states) =>
	Object.fromEntries(
		Object.entries(states).map(([role, s]) => [
			role,
			{ peers: s.peers, channels: s.channels, failures: failures(s) }
		])
	);
function percentile(sorted, fraction) {
	return sorted[
		Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))
	];
}
function summary(p) {
	return {
		from: p.from,
		to: p.to,
		elapsedMs: p.elapsedMs,
		engineMs: p.job.finished - p.job.started,
		status: p.job.result?.status,
		error: p.job.error,
		paymentStatus: p.payment?.status,
		invoiceStatus: p.received?.status
	};
}
function paid(p) {
	assert.equal(p.job.result?.status, 'COMPLETED', JSON.stringify(summary(p)));
	assert.equal(p.payment?.status, 'COMPLETED');
	assert.equal(p.received?.status, 'PAID');
	return p.job.finished - p.job.started;
}
/** `count` 1,000 sat payments, alternating direction: who paid, and how long it took. */
async function payments(count, each) {
	const samples = [];
	for (let i = 0; i < count; i++) {
		const p = await pay(
			i % 2 ? 'primary' : 'phone',
			i % 2 ? 'phone' : 'primary'
		);
		samples.push({ from: p.from, ms: paid(p) });
		await settled(ids);
		each?.(i, p);
	}
	return samples;
}
function stats(samples) {
	const sorted = samples.map((s) => s.ms).sort((a, b) => a - b);
	return {
		payments: sorted.length,
		p50: percentile(sorted, 0.5),
		p95: percentile(sorted, 0.95),
		max: sorted[sorted.length - 1],
		mean: Math.round(sorted.reduce((sum, ms) => sum + ms, 0) / sorted.length)
	};
}
/** The same figures for all the payments and for each payer's. */
const measured = (samples) => ({
	...stats(samples),
	byPayer: Object.fromEntries(
		endpoints.map((role) => [
			role,
			stats(samples.filter((s) => s.from === role))
		])
	)
});
let begun;
let dialedAt;
/**
 * Destinations each end has opened a connection to since this run began.
 * A process that restarted since then counts from nothing.
 */
function dialedSince(states) {
	return Object.fromEntries(
		endpoints.map((role) => {
			const fresh = states[role].started !== begun[role].started;
			return [
				role,
				Object.fromEntries(
					Object.entries(states[role].dialed)
						.map(([where, n]) => [
							where,
							n - (fresh ? 0 : begun[role].dialed[where] || 0)
						])
						.filter(([, n]) => n > 0)
				)
			];
		})
	);
}
/**
 * What a Porch link promises, checked three ways. On the TCP path the same
 * things are recorded and nothing is required of them.
 *
 * Packets: none of any protocol between the phone's address and the
 * primary's, as each of the two counted them. On porch-tor, none between the
 * primary and the relay either, as each of those two counted them.
 *
 * Connections: since this run began the phone has opened connections to the
 * relay and to nothing else, and the primary to the relay (porch) or to Tor
 * (porch-tor) and to nothing else. On porch-tls the relay is the TLS
 * terminator in front of it, for both. Electrum, the chain source, aside.
 *
 * Records: what each end holds for its peer names the relay and does not
 * contain the other end's address.
 */
async function leak(label) {
	const s = await statuses();
	const counts = await network.packets();
	const addr = await network.addresses();
	const since = dialedSince(s);
	const relays = s.primary.info.porch?.relays;
	const seen = (state) =>
		state.peers.map(({ host, port, transport, porch: through }) => ({
			host,
			port,
			transport,
			porch: through
		}));
	record('leak-check', {
		label,
		route,
		packets: counts,
		dialedSinceStart: since,
		primaryHoldsForPeer: seen(s.primary),
		phoneHoldsForPeer: seen(s.phone),
		relays
	});
	if (!porch) return;
	// A connection the phone has is where this path's link leads. It has none
	// while its network is away.
	for (const p of s.phone.peers)
		assert.deepEqual({ host: p.host, port: p.port }, dialedAt);
	assert.deepEqual(counts.phone.primary, zero);
	assert.deepEqual(counts.primary.phone, zero);
	for (const role of endpoints) {
		// The one container this end may open a connection to, by the name
		// the end knows it by and by its addresses.
		const may =
			route === 'porch-tls'
				? 'caddy'
				: role === 'phone' || route === 'porch'
				? 'relay'
				: 'tor';
		const hosts = [
			may === 'caddy' ? 'relay.test' : may,
			...Object.values(addr[may]).filter(Boolean)
		];
		for (const where of Object.keys(since[role])) {
			if (electrum(where)) continue;
			assert.ok(
				hosts.includes(where.slice(0, where.lastIndexOf(':'))),
				'The ' + role + ' opened a connection to ' + where
			);
		}
	}
	for (const [role, other] of [
		['primary', 'phone'],
		['phone', 'primary']
	]) {
		const held = JSON.stringify(s[role].peers);
		for (const a of Object.values(addr[other]).filter(Boolean))
			assert.ok(!held.includes(a), 'The ' + role + ' holds ' + a);
	}
	assert.equal(relays.length, 1);
	assert.equal(relays[0].proxied, route === 'porch-tor');
	if (route === 'porch-tor') {
		assert.deepEqual(counts.primary.relay, zero);
		assert.deepEqual(counts.relay.primary, zero);
	}
}
(async () => {
	const { uri } = await dial(route);
	dialedAt = target(uri);
	const start = await settled(ids);
	// Counting starts here, with the phone on this path's link. Before this
	// the fixture itself may have had the phone on another path, where it
	// was told the primary's address.
	await network.begin();
	begun = Object.fromEntries(
		endpoints.map((role) => [
			role,
			{ started: start[role].started, dialed: start[role].dialed }
		])
	);
	record('phase-start', {
		route,
		phase,
		version: start.primary.version,
		noDelay: start.primary.noDelay,
		hostLoad: hostLoad(),
		addresses: await network.addresses(),
		channels: brief(await healthy(ids))
	});
	// A process that has just started pays slower than one that has paid
	// before. Ten payments first, so the timed ones compare like with like.
	if (['all', 'baseline', 'latency'].includes(phase)) await payments(10);
	if (['all', 'baseline'].includes(phase)) {
		const samples = await payments(40, (i, p) =>
			record('baseline-payment', { route, i, ...summary(p) })
		);
		await selected(route);
		await leak('baseline');
		record('baseline-passed', {
			route,
			noDelay: start.primary.noDelay,
			hostLoad: hostLoad(),
			engineMs: measured(samples),
			packets: await network.packets(),
			channels: brief(await healthy(ids))
		});
	}
	if (['all', 'latency'].includes(phase) && route !== 'porch-tor') {
		// Everything between the two ends takes `ms` longer, one way: held at
		// the relay on the Porch path, where every frame passes once, and at
		// both ends on the TCP path. What a payment gains per millisecond is
		// then the same question on both, and Tor brings its own.
		const held = porch ? ['relay'] : ['phone', 'primary'];
		const points = [];
		try {
			for (const ms of [0, 20, 40]) {
				for (const role of held) await network.latency(role, ms);
				points.push({
					ms,
					hostLoad: hostLoad(),
					...measured(await payments(20))
				});
				record('latency-point', { route, ...points[points.length - 1] });
			}
		} finally {
			for (const role of held) await network.latency(role, 0);
		}
		record('latency-passed', {
			route,
			noDelay: start.primary.noDelay,
			points,
			// Milliseconds a payment gains for each millisecond between the
			// two ends, one way. From the means: a payment takes a whole
			// number of trips across, not always the same number, so a
			// median sits on one of the steps.
			perMs: (points[2].mean - points[0].mean) / (points[2].ms - points[0].ms)
		});
	}
	if (['all', 'restart'].includes(phase)) {
		// One process restarts and nothing is redialed by hand. The phone is
		// what opening the app is; the primary and the relay are what an
		// update or a crash of each is.
		const lost = (state) =>
			state.events.filter((e) => e.name === 'peer:disconnect').length;
		for (const role of porch ? ['phone', 'primary', 'relay'] : endpoints) {
			for (let i = 0; i < rounds; i++) {
				await selected(route);
				const before = await healthy(ids);
				// The rules live in the container's network namespace, which a
				// restart replaces: keep what they counted, and write them
				// again before the process is up.
				if (network.WATCH[role]) await network.carry(role);
				const started = Date.now();
				await docker('restart', names[role]);
				const restarted = Date.now();
				if (network.WATCH[role]) await network.write(role);
				await network.addresses();
				// An end that kept running has to notice the connection is
				// gone, or its channel reads usable on a connection that is not
				// there any more.
				await wait(
					'the connection seen lost',
					async () => {
						for (const end of endpoints) {
							if (end === role) continue;
							if (lost(await rpc(end, 'status')) <= lost(before[end]))
								return false;
						}
						return true;
					},
					180000
				);
				const recovered = await settled(ids, 420000);
				await selected(route);
				const usableMs = Date.now() - restarted;
				const p = await pay('phone', 'primary');
				paid(p);
				const firstPaymentMs = Date.now() - restarted;
				const back = await pay('primary', 'phone');
				paid(back);
				const after = await settled(ids);
				await leak('after ' + role + ' restart ' + (i + 1));
				record('restart-passed', {
					route,
					role,
					i,
					restartMs: restarted - started,
					usableMs,
					firstPaymentMs,
					// From the start of the restarted process to its channel
					// reading usable, as the process timed it.
					processUsableMs: after[role]?.events.find((e) => e.name === 'usable')
						?.detail.sinceStartMs,
					recovered: brief(recovered),
					payments: [summary(p), summary(back)]
				});
				// Allow the normal stability window to reset the reconnect backoff.
				await delay(cooldownMs);
			}
		}
	}
	if (['all', 'outages'].includes(phase)) {
		// The phone loses its network and gets it back. Recovery uses the
		// engine's default timers: nothing is redialed and no process restarts.
		for (const seconds of [30, 120, 300]) {
			await selected(route);
			await healthy(ids);
			record('outage-start', { route, seconds });
			await leak('before the ' + seconds + ' s outage');
			await network.outage('phone', true);
			const started = Date.now();
			for (let elapsed = 0; elapsed < seconds; elapsed += 30) {
				await delay(Math.min(30, seconds - elapsed) * 1000);
				record('outage-progress', {
					route,
					seconds,
					elapsedSeconds: (Date.now() - started) / 1000
				});
			}
			const during = brief(await statuses());
			await leak('during the ' + seconds + ' s outage');
			await network.outage('phone', false);
			const restored = Date.now();
			const recovered = await settled(ids, 420000);
			const usableMs = Date.now() - restored;
			const p = await pay('phone', 'primary');
			paid(p);
			const firstPaymentMs = Date.now() - restored;
			const back = await pay('primary', 'phone');
			paid(back);
			await settled(ids);
			await selected(route);
			await leak('after the ' + seconds + ' s outage');
			record('outage-passed', {
				route,
				seconds,
				blockedMs: restored - started,
				usableMs,
				firstPaymentMs,
				during,
				recovered: brief(recovered),
				payments: [summary(p), summary(back)]
			});
			await delay(cooldownMs);
		}
	}
	await leak('end');
	const counts = await network.packets();
	// The control for the counters: where the two ends do talk to each
	// other, or the primary to the relay, the same rules count it.
	if (!porch) assert.ok(counts.phone.primary.out > 0);
	if (route === 'porch') assert.ok(counts.primary.relay.out > 0);
	fs.writeFileSync(
		path.join(base, route + '-' + phase + '-final.json'),
		JSON.stringify(await statuses(), null, 2)
	);
	record('phase-passed', { route, phase, packets: counts });
})()
	.catch((error) => {
		record('phase-failed', { route, phase, error: error.stack });
		process.exitCode = 1;
	})
	.finally(async () => {
		try {
			await network.outage('phone', false);
			for (const role of ['phone', 'primary', 'relay'])
				await network.latency(role, 0);
		} catch (error) {
			console.error(error);
			process.exitCode = 1;
		}
	});
