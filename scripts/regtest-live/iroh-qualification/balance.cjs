const { pay, settled, record, fs, base, path, assert } = require('./lab.cjs');
(async () => {
	const { ids } = JSON.parse(fs.readFileSync(path.join(base, 'channel.json')));
	const result = await pay('primary', 'phone', { amount: 300000 });
	record('balance-payment', result);
	assert.equal(result.job.result?.status, 'COMPLETED');
	record('balanced', {
		channels: Object.fromEntries(
			Object.entries(await settled(ids)).map(([k, s]) => [k, s.channels])
		)
	});
})().catch((e) => {
	console.error(e.stack);
	process.exitCode = 1;
});
