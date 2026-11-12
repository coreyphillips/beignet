'use strict';
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const {
	base,
	routes,
	endpoints,
	rpc,
	wait,
	statuses,
	link,
	expected,
	via,
	target,
	assert
} = require('./lab.cjs');
const exec = promisify(execFile);
// QUALIFY_TCP_NODELAY=true: both endpoints with Nagle's algorithm off on their
// TCP peer sockets (see node.cjs).
const noDelay = process.env.QUALIFY_TCP_NODELAY === 'true';

/**
 * Have the primary reachable by one path and no other, starting it again
 * with that setting when it runs with a different one. Resolves with the
 * primary's status once a link for the path can be dialed.
 */
async function reach(route) {
	assert.ok(routes.includes(route));
	const now = await statuses().catch(() => ({}));
	const again = [];
	if (now.primary?.route !== route || now.primary.noDelay !== noDelay)
		again.push('primary');
	if (now.phone?.noDelay !== noDelay) again.push('phone');
	if (again.length > 0)
		await exec('docker', ['compose', 'up', '-d', '--no-deps', ...again], {
			cwd: base,
			env: {
				...process.env,
				QUALIFY_PATH: route,
				QUALIFY_TCP_NODELAY: String(noDelay)
			},
			timeout: 180000
		});
	await wait('the phone answering', () =>
		rpc('phone', 'status').catch(() => false)
	);
	// The first time, Tor needs a while to publish the relay's onion service.
	return wait(
		'the primary reachable by ' + route,
		async () => {
			const primary = await rpc('primary', 'status').catch(() => undefined);
			if (primary?.route !== route || primary.noDelay !== noDelay) return false;
			if (route === 'tcp') return primary.info.listening ? primary : false;
			return primary.info.porch?.relays[0]?.state === 'ready' &&
				link(route, primary)
				? primary
				: false;
		},
		600000,
		1000
	);
}
/** Each end reporting the other connected the way the path says. */
function selected(route) {
	const want = expected(route);
	return wait(
		route + ' path in use on both ends',
		async () => {
			const s = await statuses().catch(() => undefined);
			return s &&
				endpoints.every((role) =>
					s[role].peers.some(
						(p) => p.state === 'ready' && via(p) === want[role]
					)
				)
				? s
				: false;
		},
		420000
	);
}
/**
 * Have the phone connected to the primary by the path's link, whatever it
 * was connected by before.
 */
async function dial(route) {
	const primary = await reach(route);
	const uri = link(route, primary);
	const peer = (await rpc('phone', 'status')).peers.find(
		(p) => p.pubkey === primary.info.nodeId
	);
	// The link of another Porch path can lead to the same relay and the same
	// route, so the phone is held to this path's own.
	const at = target(uri);
	if (
		!(
			peer?.state === 'ready' &&
			via(peer) === expected(route).phone &&
			peer.host === at.host &&
			peer.port === at.port
		)
	) {
		await rpc('phone', 'disconnect', { peer: primary.info.nodeId }).catch(
			() => undefined
		);
		await wait(
			'the phone connected by ' + route,
			() =>
				rpc('phone', 'connect', { uri }).then(
					() => true,
					() => false
				),
			180000,
			1000
		);
	}
	await selected(route);
	return { primary, uri };
}
module.exports = { reach, selected, dial };
