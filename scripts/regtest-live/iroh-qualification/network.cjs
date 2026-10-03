'use strict';
const { execFile } = require('node:child_process');
const { docker, names, assert } = require('./lab.cjs');
async function restore(tool, input) {
	await new Promise((resolve, reject) => {
		const child = execFile(
			'docker',
			['exec', '-i', names.phone, tool, '--noflush'],
			{ encoding: 'utf8', timeout: 15000 },
			(error, stdout, stderr) => {
				if (error) reject(Error(stderr || error.message));
				else resolve(stdout);
			}
		);
		child.stdin.on('error', reject);
		child.stdin.end(input);
	});
}
async function firewall(mode) {
	assert.ok(['direct', 'relay', 'outage'].includes(mode));
	const info = JSON.parse(await docker('inspect', names.phone))[0];
	assert.equal(info.Config.Labels['beignet.test'], 'iroh-qualification');
	assert.equal(info.HostConfig.NetworkMode, 'beignet-iroh-qualification');
	assert.equal(Object.keys(info.HostConfig.PortBindings || {}).length, 0);
	for (const tool of ['iptables', 'ip6tables']) {
		const rules = ['*filter'];
		for (const [chain, hook, iface] of [
			['BQ_OUT', 'OUTPUT', '-o'],
			['BQ_IN', 'INPUT', '-i']
		]) {
			const run = (...args) => docker('exec', names.phone, tool, '-w', ...args);
			try {
				await run('-N', chain);
			} catch (e) {
				if (!e.stderr?.includes('Chain already exists')) throw e;
			}
			try {
				await run('-C', hook, '-j', chain);
			} catch {
				await run('-I', hook, '1', '-j', chain);
			}
			rules.push('-F ' + chain, '-A ' + chain + ' ' + iface + ' lo -j RETURN');
			if (mode === 'relay') {
				rules.push(
					'-A ' +
						chain +
						' -p udp ' +
						(chain === 'BQ_OUT' ? '--dport' : '--sport') +
						' 53 -j RETURN'
				);
				rules.push('-A ' + chain + ' -p udp -j DROP');
			} else if (mode === 'outage') rules.push('-A ' + chain + ' -j DROP');
		}
		// A single filter-table commit replaces both chains, so returning from
		// a full outage to relay-only cannot briefly admit direct UDP traffic.
		rules.push('COMMIT', '');
		await restore(tool + '-restore', rules.join('\n'));
	}
}
async function counters() {
	return Object.fromEntries(
		await Promise.all(
			['iptables', 'ip6tables'].map(async (tool) => [
				tool,
				await docker('exec', names.phone, tool, '-w', '-nvxL')
			])
		)
	);
}
module.exports = { firewall, counters };
