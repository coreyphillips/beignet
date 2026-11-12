'use strict';
const {
	rpc,
	btc,
	wait,
	record,
	statuses,
	settled,
	pay,
	fs,
	path,
	base,
	routes,
	assert
} = require('./lab.cjs');
const { dial } = require('./route.cjs');
// The channel is opened over the path named here: through the relay unless
// told otherwise, so that the opening itself is part of what is tried.
const route = process.argv[2] || 'porch';
(async () => {
	assert.ok(routes.includes(route));
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
	await rpc('primary', 'trust', { peer: state.phone.info.nodeId });
	await rpc('phone', 'trust', { peer: state.primary.info.nodeId });
	const { uri } = await dial(route);
	record('connected', { route, uri, ...(await statuses()) });
	const opened = await rpc('primary', 'open', {
		peer: state.phone.info.nodeId
	});
	record('opened', { route, opened });
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
		JSON.stringify({ ids }, null, 2)
	);
	record('funded-channel', {
		route,
		ids,
		primary: state.primary.channels,
		phone: state.phone.channels
	});
	// The primary funded the channel alone; give the phone something to send.
	await settled(ids);
	const balance = await pay('primary', 'phone', { amount: 300000 });
	assert.equal(balance.job.result?.status, 'COMPLETED');
	record('balanced', {
		channels: Object.fromEntries(
			Object.entries(await settled(ids)).map(([k, s]) => [k, s.channels])
		)
	});
})().catch((error) => {
	console.error(error.stack);
	process.exitCode = 1;
});
