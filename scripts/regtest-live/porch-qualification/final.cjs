'use strict';
const {
	healthy,
	btc,
	record,
	fs,
	path,
	base,
	assert,
	wait,
	statuses
} = require('./lab.cjs');
(async () => {
	const { ids } = JSON.parse(fs.readFileSync(path.join(base, 'channel.json')));
	assert.equal(JSON.parse(await btc('getblockchaininfo')).chain, 'regtest');
	await wait('Electrum restored on both endpoints', async () =>
		Object.values(await statuses()).every((s) => s.health.electrumConnected)
	);
	const state = await healthy(ids);
	const channel = state.primary.channels[0];
	const utxo = JSON.parse(
		await btc(
			'gettxout',
			channel.fundingTxid,
			String(channel.fundingOutputIndex),
			'true'
		)
	);
	assert.ok(utxo && utxo.confirmations >= 1, 'Funding output spent or missing');
	assert.equal(utxo.value, 0.01);
	record('final-channel-proof', {
		ids,
		channels: Object.fromEntries(
			Object.entries(state).map(([role, s]) => [role, s.channels])
		),
		fundingOutputUnspent: true,
		fundingConfirmations: utxo.confirmations,
		channelFailures: 0
	});
	fs.writeFileSync(
		path.join(base, 'qualification-final.json'),
		JSON.stringify(state, null, 2)
	);
})().catch((error) => {
	console.error(error.stack);
	process.exitCode = 1;
});
