'use strict';
const {
	base,
	delay,
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
const { firewall, counters } = require('./network.cjs');
const { ids, primaryUri } = JSON.parse(
	fs.readFileSync(path.join(base, 'channel.json'))
);
const mode = process.argv[2];
const phase = process.argv[3] || 'all';
assert.ok(['direct', 'relay'].includes(mode));
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
		mode + ' path selected on both ends',
		async () => {
			const s = await statuses();
			return Object.values(s).every((endpoint) =>
				endpoint.peers.some(
					(p) => p.transport === 'iroh' && p.iroh?.path === mode
				)
			)
				? s
				: false;
		},
		120000
	);
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
	await firewall(mode);
	await selected();
	await settled(ids);
	record('phase-start', {
		mode,
		phase,
		firewallRevision: 'atomic-v1',
		channels: brief(await healthy(ids))
	});
	if (['all', 'baseline'].includes(phase)) {
		for (let i = 0; i < 20; i++) {
			const p = await pay(
				i % 2 ? 'primary' : 'phone',
				i % 2 ? 'phone' : 'primary'
			);
			paid(p);
			await settled(ids);
			await selected();
			record('baseline-payment', { mode, i, ...summary(p) });
		}
		record('baseline-passed', {
			mode,
			payments: 20,
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
			await firewall(mode);
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
		await firewall(mode).catch((error) => {
			console.error(error);
			process.exitCode = 1;
		});
	});
