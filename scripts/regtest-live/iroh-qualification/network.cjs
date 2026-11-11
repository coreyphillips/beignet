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
/** The primary container's addresses on the qualification network. */
async function primaryAddresses() {
	const info = JSON.parse(await docker('inspect', names.primary))[0];
	const network = info.NetworkSettings.Networks['beignet-iroh-qualification'];
	assert.ok(network?.IPAddress, 'The primary has no address on the network');
	return {
		iptables: network.IPAddress,
		ip6tables: network.GlobalIPv6Address || undefined
	};
}
async function firewall(mode) {
	assert.ok(['direct', 'relay', 'outage'].includes(mode));
	const primary = await primaryAddresses();
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
			// No target: these only count what passes between the two
			// containers, whatever the rules below then do with it. The second
			// counts the datagrams among them, which is what Iroh would send.
			if (primary[tool]) {
				const pair =
					'-A ' +
					chain +
					(chain === 'BQ_OUT' ? ' -d ' : ' -s ') +
					primary[tool];
				rules.push(pair, pair + ' -p udp');
			}
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
/**
 * Packets between the phone and the primary's own address since the firewall
 * rules were last written: `out` and `in` count every protocol, `udpOut` and
 * `udpIn` the datagrams among them. A relayed connection puts none here, as
 * both ends talk to the relay on the Internet. A phone that holds an old
 * address for the primary still probes it (`out`), and the primary's kernel
 * may answer that nothing listens there (`in`, as ICMP); a datagram back from
 * the primary (`udpIn`) is the one thing a relay-only endpoint cannot send.
 */
async function pairPackets() {
	const primary = await primaryAddresses();
	const total = { out: 0, in: 0, udpOut: 0, udpIn: 0 };
	for (const tool of ['iptables', 'ip6tables']) {
		if (!primary[tool]) continue;
		for (const [chain, flag, key, udpKey] of [
			['BQ_OUT', '-d', 'out', 'udpOut'],
			['BQ_IN', '-s', 'in', 'udpIn']
		]) {
			const listing = await docker(
				'exec',
				names.phone,
				tool,
				'-w',
				'-v',
				'-S',
				chain
			);
			const rules = listing
				.split('\n')
				.filter((line) =>
					line.includes(' ' + flag + ' ' + primary[tool] + '/')
				);
			const count = (rule) => {
				const counted = rule && /-c (\d+) \d+/.exec(rule);
				assert.ok(counted, 'No pair counter in ' + tool + ' ' + chain);
				return Number(counted[1]);
			};
			total[key] += count(rules.find((rule) => !rule.includes('-p udp')));
			total[udpKey] += count(rules.find((rule) => rule.includes('-p udp')));
		}
	}
	return total;
}
module.exports = { firewall, counters, pairPackets };
