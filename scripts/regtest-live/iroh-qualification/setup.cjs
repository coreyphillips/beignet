'use strict';
const {
	rpc,
	btc,
	wait,
	record,
	statuses,
	fs,
	path,
	base,
	assert
} = require('./lab.cjs');
(async () => {
	assert.equal(JSON.parse(await btc('getblockchaininfo')).chain, 'regtest');
	let state = await statuses();
	for (const s of Object.values(state)) {
		assert.equal(s.info.network, 'regtest');
		assert.equal(s.channels.length, 0);
	}
	if ((await rpc('primary', 'refresh')).onchain < 2000000) {
		const address = await rpc('primary', 'address');
		await btc('sendtoaddress', address, '0.02000000');
		await btc('-generate', '3');
	}
	await wait(
		'primary funded',
		async () => (await rpc('primary', 'refresh')).onchain >= 2000000
	);
	state = await wait('Iroh relay hints published', async () => {
		const endpoints = await statuses();
		return Object.values(endpoints).every((endpoint) =>
			endpoint.info.irohUri?.includes('?relay=')
		)
			? endpoints
			: false;
	});
	await rpc('primary', 'trust', { peer: state.phone.info.nodeId });
	await rpc('phone', 'trust', { peer: state.primary.info.nodeId });
	await rpc('phone', 'connect', { uri: state.primary.info.irohUri });
	record('connected', await statuses());
	const opened = await rpc('primary', 'open', {
		peer: state.phone.info.nodeId
	});
	record('opened', { opened });
	state = await wait('channel usable', async () => {
		const s = await statuses();
		return Object.values(s).every((endpoint) =>
			endpoint.channels.some((c) => c.htlcUsable)
		)
			? s
			: false;
	});
	await btc('-generate', '6');
	const ids = Object.fromEntries(
		Object.entries(state).map(([role, s]) => [role, s.channels[0].channelId])
	);
	fs.writeFileSync(
		path.join(base, 'channel.json'),
		JSON.stringify(
			{
				ids,
				primaryUri: state.primary.info.irohUri,
				phoneUri: state.phone.info.irohUri
			},
			null,
			2
		)
	);
	record('funded-channel', {
		ids,
		primary: state.primary.channels,
		phone: state.phone.channels,
		peers: state.phone.peers
	});
})().catch((error) => {
	console.error(error.stack);
	process.exitCode = 1;
});
