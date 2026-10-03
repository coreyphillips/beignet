'use strict';
// Run inside the payer container to remove Docker round trips between payments.
const assert = require('node:assert/strict');
const input = JSON.parse(process.argv[2]);
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function call(op, body) {
	const response = await fetch('http://127.0.0.1:8089', {
		method: 'POST',
		body: JSON.stringify({ op, body })
	});
	const result = await response.json();
	assert.equal(result.ok, true, JSON.stringify(result));
	return result.value;
}
(async () => {
	const warmup = await call('pay', { bolt11: input.warmupBolt11 });
	const deadline = Date.now() + 100000;
	let job;
	while (Date.now() < deadline) {
		job = await call('job', { id: warmup.id });
		if (job.done) break;
		await delay(5);
	}
	assert.equal(job?.result?.status, 'COMPLETED');
	// The next payment starts as soon as the previous payment API returns.
	// Do not wait for remaining channel commitment work before the cut.
	const next = await call('pay', input.target);
	console.log(JSON.stringify({ id: next.id, warmupFinished: job.finished }));
})().catch((error) => {
	console.error(error.stack);
	process.exitCode = 1;
});
