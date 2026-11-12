'use strict';
const {
	base,
	names,
	delay,
	docker,
	rpc,
	wait,
	record,
	statuses,
	healthy,
	settled,
	pay,
	assert,
	fs,
	path
} = require('./lab.cjs');
const { firewall, counters, pairPackets } = require('./network.cjs');
const { ids, primaryUri } = JSON.parse(
	fs.readFileSync(path.join(base, 'channel.json'))
);
const mode = process.argv[2];
const phase = process.argv[3] || 'all';
assert.ok(['direct', 'relay', 'relay-only'].includes(mode));
// relay-only: the primary runs with irohRelayOnly and the firewall is left
// open, so a direct path would be taken if the primary offered one.
const relayOnly = mode === 'relay-only';
const rules = relayOnly ? 'direct' : mode;
const expectedPath = mode === 'direct' ? 'direct' : 'relay';
const brief = (states) =>
	Object.fromEntries(
		Object.entries(states).map(([role, s]) => [
			role,
			{
				peers: s.peers,
				channels: s.channels,
				failures: s.events.filter((e) =>
					/channel:(errored|closed|voided)/.test(e.name)
				)
			}
		])
	);
async function selected() {
	return wait(
		expectedPath + ' path selected on both ends',
		async () => {
			const s = await statuses();
			return Object.values(s).every((endpoint) =>
				endpoint.peers.some(
					(p) => p.transport === 'iroh' && p.iroh?.path === expectedPath
				)
			)
				? s
				: false;
		},
		120000
	);
}
const loopback = (address) =>
	/^127\./.test(address) || /^\[::1\]/.test(address);
function percentile(sorted, fraction) {
	return sorted[
		Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))
	];
}
// Set when the phone met the primary before relay-only was switched on: it
// then still holds the addresses it learned, and the check below is what a
// relay-only endpoint owes such a peer rather than what it owes a stranger.
const phoneKnowsPrimary = process.env.QUALIFY_PHONE_KNOWS_PRIMARY === 'true';
const primaryEndpointId = /@iroh:([0-9a-f]{64})/.exec(primaryUri)?.[1];
const learnedByPhone = () =>
	rpc('phone', 'iroh-learned', { endpointId: primaryEndpointId });
let phaseStart;
/** Path samples each end has taken since this phase began. */
function sincePhaseStart(states) {
	return Object.fromEntries(
		Object.entries(states).map(([role, state]) => {
			const from = phaseStart.samples[role];
			const now = state.pathSamples;
			// A restarted process counts from zero again.
			const restarted = Object.keys(now).some((key) => now[key] < from[key]);
			return [
				role,
				Object.fromEntries(
					Object.keys(now).map((key) => [
						key,
						now[key] - (restarted ? 0 : from[key])
					])
				)
			];
		})
	);
}
/**
 * The relay-only promise. A no-op in the other modes.
 *
 * To a stranger (the default): no path sample on either end has read direct
 * since its process started, the phone's own Iroh stack holds no address for
 * the primary that it could route to, and no packet of any kind has passed
 * between the two containers' addresses since the firewall rules were last
 * written.
 *
 * To a peer that knew the primary's address already
 * (QUALIFY_PHONE_KNOWS_PRIMARY=true): the phone may hold and probe the
 * addresses it had when the phase began, and no others. No path sample has
 * read direct since the phase began, and the primary has sent the phone no
 * datagram from its own address.
 */
async function leak(label) {
	if (!relayOnly) return;
	const s = await statuses();
	const samples = Object.fromEntries(
		Object.entries(s).map(([role, state]) => [role, state.pathSamples])
	);
	const inPhase = sincePhaseStart(s);
	const learned = await learnedByPhone();
	const routable = learned.directAddresses.filter((a) => !loopback(a));
	const fresh = routable.filter((a) => !phaseStart.known.includes(a));
	const pair = await pairPackets();
	const violations = s.primary.events.filter((e) => e.name === 'node:error');
	record('relay-only-leak-check', {
		label,
		relayOnlyMode: s.primary.info.irohRelayOnlyMode,
		phoneKnowsPrimary,
		samples,
		samplesSincePhaseStart: inPhase,
		learnedAddresses: learned.directAddresses.length,
		routableAddresses: routable.length,
		addressesLearnedSincePhaseStart: fresh.length,
		pairPackets: pair,
		violations
	});
	assert.equal(s.primary.info.irohRelayOnly, true);
	assert.equal(samples.primary.direct, 0);
	assert.equal(inPhase.primary.direct + inPhase.phone.direct, 0);
	assert.ok(samples.primary.relay > 0 && samples.phone.relay > 0);
	assert.equal(fresh.length, 0);
	assert.equal(pair.udpIn, 0);
	assert.equal(violations.length, 0);
	if (phoneKnowsPrimary) return;
	assert.equal(samples.phone.direct, 0);
	assert.equal(routable.length, 0);
	assert.deepEqual(pair, { out: 0, in: 0, udpOut: 0, udpIn: 0 });
}
function summary(p) {
	return {
		from: p.from,
		to: p.to,
		elapsedMs: p.elapsedMs,
		engineMs: p.job.finished - p.job.started,
		cutAt: p.job.cutAt,
		cutOffsetMs: p.job.cutAt ? p.job.cutAt - p.job.started : null,
		observed: p.job.observed,
		status: p.job.result?.status,
		error: p.job.error,
		paymentStatus: p.payment?.status,
		invoiceStatus: p.received?.status,
		explicitRedial: p.explicitRedial,
		warmupGapMs: p.warmupGapMs,
		warmupInvoiceStatus: p.warmupInvoiceStatus
	};
}
function paid(p) {
	assert.equal(p.job.result?.status, 'COMPLETED', JSON.stringify(summary(p)));
	assert.equal(p.payment?.status, 'COMPLETED');
	assert.equal(p.received?.status, 'PAID');
	if (p.warmupGapMs !== undefined) {
		assert.ok(p.warmupGapMs >= 0 && p.warmupGapMs < 100);
		assert.equal(p.warmupInvoiceStatus, 'PAID');
	}
}
(async () => {
	await firewall(rules);
	const begun = await selected();
	await settled(ids);
	if (relayOnly) {
		const known = (await learnedByPhone()).directAddresses.filter(
			(a) => !loopback(a)
		);
		// Only a phone declared to have met the primary may start with any.
		if (!phoneKnowsPrimary) assert.equal(known.length, 0);
		phaseStart = {
			known,
			samples: Object.fromEntries(
				Object.entries(begun).map(([role, state]) => [role, state.pathSamples])
			)
		};
	}
	record('phase-start', {
		mode,
		phase,
		firewallRevision: 'atomic-v1',
		channels: brief(await healthy(ids))
	});
	if (['all', 'baseline'].includes(phase)) {
		const engineMs = [];
		for (let i = 0; i < 20; i++) {
			const p = await pay(
				i % 2 ? 'primary' : 'phone',
				i % 2 ? 'phone' : 'primary'
			);
			paid(p);
			await settled(ids);
			await selected();
			engineMs.push(p.job.finished - p.job.started);
			record('baseline-payment', { mode, i, ...summary(p) });
		}
		engineMs.sort((a, b) => a - b);
		await leak('baseline');
		record('baseline-passed', {
			mode,
			payments: 20,
			engineMs: {
				p50: percentile(engineMs, 0.5),
				p90: percentile(engineMs, 0.9),
				max: engineMs[engineMs.length - 1]
			},
			pairPackets: await pairPackets(),
			firewall: await counters(),
			channels: brief(await healthy(ids))
		});
	}
	if (['all', 'outages'].includes(phase)) {
		// All recovery attempts use the released engine's default timers. Never
		// explicitly redial or restart a node during these outage scenarios.
		for (const seconds of [30, 120, 300]) {
			await selected();
			await healthy(ids);
			record('outage-start', { mode, seconds });
			await leak('before the ' + seconds + ' s outage');
			await firewall('outage');
			const started = Date.now();
			for (let elapsed = 0; elapsed < seconds; elapsed += 30) {
				await delay(Math.min(30, seconds - elapsed) * 1000);
				record('outage-progress', {
					mode,
					seconds,
					elapsedSeconds: (Date.now() - started) / 1000
				});
			}
			const during = brief(await statuses());
			const blocked = await counters();
			await leak('during the ' + seconds + ' s outage');
			await firewall(rules);
			const restored = Date.now();
			const recovered = await settled(ids, 420000);
			const usableMs = Date.now() - restored;
			const p = await pay('phone', 'primary');
			paid(p);
			const firstPaymentMs = Date.now() - restored;
			const back = await pay('primary', 'phone');
			paid(back);
			await settled(ids);
			await selected();
			await leak('after the ' + seconds + ' s outage');
			record('outage-passed', {
				mode,
				seconds,
				blockedMs: restored - started,
				usableMs,
				firstPaymentMs,
				during,
				blocked,
				recovered: brief(recovered),
				payments: [summary(p), summary(back)]
			});
			// Allow the normal stability window to reset the reconnect backoff.
			await delay(61000);
		}
	}
	if (phase === 'restart') {
		// One process restarts and nothing is redialed by hand, so the two ends
		// set up a connection from nothing while the counters run. The primary
		// by default; QUALIFY_RESTART_ROLE=phone restarts the phone, which is
		// what opening the app is. Not part of `all`: the outage scenarios
		// never restart a node.
		const role = process.env.QUALIFY_RESTART_ROLE || 'primary';
		assert.ok(['primary', 'phone'].includes(role));
		for (let i = 0; i < 3; i++) {
			await selected();
			await healthy(ids);
			await firewall(rules);
			const started = Date.now();
			await docker('restart', names[role]);
			const restarted = Date.now();
			// The rules live in the phone's network namespace, which a restart
			// replaces: write them again before its engine is up.
			if (role === 'phone') await firewall(rules);
			await wait('the ' + role + ' answering again', () =>
				rpc(role, 'status').catch(() => false)
			);
			const recovered = await settled(ids, 420000);
			await selected();
			const usableMs = Date.now() - restarted;
			const p = await pay('phone', 'primary');
			paid(p);
			const firstPaymentMs = Date.now() - restarted;
			const back = await pay('primary', 'phone');
			paid(back);
			await settled(ids);
			await selected();
			await leak('after ' + role + ' restart ' + (i + 1));
			record('restart-passed', {
				mode,
				role,
				i,
				restartMs: restarted - started,
				usableMs,
				firstPaymentMs,
				pairPackets: await pairPackets(),
				recovered: brief(recovered),
				payments: [summary(p), summary(back)]
			});
			await delay(61000);
		}
	}
	if (['all', 'cuts'].includes(phase)) {
		let cuts = 0,
			attempts = 0;
		const offsets = [20, 45, 70, 95, 120, 150, 180, 220, 250];
		while (cuts < 30 && attempts < 150) {
			await selected();
			await settled(ids);
			const from = attempts % 2 ? 'primary' : 'phone';
			const p = await pay(from, from === 'phone' ? 'primary' : 'phone', {
				cutAfterMs: offsets[attempts % offsets.length],
				reconnect: primaryUri
			});
			attempts++;
			if (p.job.cutAt) cuts++;
			record('cut-attempt', { mode, attempt: attempts, cuts, ...summary(p) });
			paid(p);
			await settled(ids);
			const probe = await pay(from === 'phone' ? 'primary' : 'phone', from);
			paid(probe);
			await settled(ids);
			record('cut-recovery-probe', {
				mode,
				attempt: attempts,
				...summary(probe)
			});
			await healthy(ids);
		}
		assert.equal(cuts, 30, 'Too few observed in-flight cuts');
		await leak('cuts');
		record('cuts-passed', {
			mode,
			cuts,
			attempts,
			channels: brief(await healthy(ids)),
			firewall: await counters()
		});
	}
	fs.writeFileSync(
		path.join(base, mode + '-' + phase + '-final.json'),
		JSON.stringify(await statuses(), null, 2)
	);
	record('phase-passed', { mode, phase });
})()
	.catch((error) => {
		record('phase-failed', { mode, phase, error: error.stack });
		process.exitCode = 1;
	})
	.finally(async () => {
		await firewall(rules).catch((error) => {
			console.error(error);
			process.exitCode = 1;
		});
	});
