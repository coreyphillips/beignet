'use strict';
const { execFile } = require('node:child_process');
const { docker, names, assert } = require('./lab.cjs');
const NETWORK = 'beignet-porch-qualification';
const TOOLS = ['iptables', 'ip6tables'];
const CHAINS = [
	['BQ_OUT', 'OUTPUT', '-o', '-d', 'out'],
	['BQ_IN', 'INPUT', '-i', '-s', 'in']
];
// Whose address each container counts packets with. Both ends of a pair
// count, so one container's restart (which empties its rules) is covered by
// the other's.
const WATCH = {
	phone: ['primary'],
	primary: ['phone', 'relay'],
	relay: ['primary']
};
const known = {};
const carried = {};
const dropping = new Set();
// Containers whose rules were written for addresses that may have changed.
const stale = new Set();

async function inspect(role) {
	const info = JSON.parse(await docker('inspect', names[role]))[0];
	assert.equal(info.Config.Labels['beignet.test'], 'porch-qualification');
	assert.equal(info.HostConfig.NetworkMode, NETWORK);
	assert.equal(Object.keys(info.HostConfig.PortBindings || {}).length, 0);
	const network = info.NetworkSettings.Networks[NETWORK];
	assert.ok(network?.IPAddress, 'No address on the network: ' + role);
	return {
		iptables: network.IPAddress,
		ip6tables: network.GlobalIPv6Address || undefined
	};
}
/** A container's addresses on the fixture network, as first seen. */
async function address(role) {
	return (known[role] ??= await inspect(role));
}
/** Addresses of every container, checked against what the rules were written for. */
async function addresses() {
	const all = {};
	for (const role of Object.keys(names)) {
		all[role] = await inspect(role);
		assert.deepEqual(all[role], await address(role), role + ' moved');
	}
	return all;
}
/**
 * Start counting from nothing, with the addresses the containers have now:
 * one created anew since the last run may have another.
 */
async function begin() {
	for (const role of Object.keys(known)) delete known[role];
	for (const role of Object.keys(carried)) delete carried[role];
	for (const role of Object.keys(WATCH)) stale.add(role);
	dropping.clear();
	for (const role of Object.keys(WATCH)) await write(role);
}
const tool = (role, name, ...args) =>
	docker('exec', names[role], name, '-w', ...args);

/** What a container's rules have counted since they were last written or read out. */
async function counted(role) {
	const totals = {};
	for (const other of WATCH[role]) totals[other] = { out: 0, in: 0 };
	for (const name of TOOLS) {
		for (const [chain, , , flag, key] of CHAINS) {
			// A container that was just started has no rules yet.
			const chains = await tool(role, name, '-S');
			if (!chains.split('\n').includes('-N ' + chain)) return undefined;
			const listing = await tool(role, name, '-v', '-S', chain);
			for (const other of WATCH[role]) {
				const addr = (await address(other))[name];
				if (!addr) continue;
				const rule = listing
					.split('\n')
					.find((line) => line.includes(' ' + flag + ' ' + addr + '/'));
				const count = rule && /-c (\d+) \d+/.exec(rule);
				assert.ok(count, 'No counter for ' + other + ' in ' + role);
				totals[other][key] += Number(count[1]);
			}
		}
	}
	return totals;
}
/**
 * Move what a container's rules have counted into the harness, and zero
 * them. Called before anything that empties the rules: a rewrite, or a
 * restart of the container, which replaces its network namespace.
 */
async function carry(role) {
	const now = await counted(role);
	if (!now) return;
	for (const name of TOOLS)
		for (const [chain] of CHAINS) await tool(role, name, '-Z', chain);
	carried[role] ??= {};
	for (const [other, count] of Object.entries(now)) {
		const sum = (carried[role][other] ??= { out: 0, in: 0 });
		sum.out += count.out;
		sum.in += count.in;
	}
}
async function restore(role, name, input) {
	await new Promise((resolve, reject) => {
		const child = execFile(
			'docker',
			['exec', '-i', names[role], name, '--noflush'],
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
/**
 * Write a container's rules: count every packet to and from the addresses
 * it watches, of any protocol, and drop everything but loopback while it is
 * in an outage. The counting rules have no target, so they see what passes
 * whatever the rules after them do with it.
 */
async function write(role) {
	// Rules written for other addresses have nothing to carry over.
	if (!stale.delete(role)) await carry(role);
	for (const name of TOOLS) {
		const rules = ['*filter'];
		for (const [chain, hook, iface, flag] of CHAINS) {
			try {
				await tool(role, name, '-N', chain);
			} catch (error) {
				if (!error.stderr?.includes('Chain already exists')) throw error;
			}
			try {
				await tool(role, name, '-C', hook, '-j', chain);
			} catch {
				await tool(role, name, '-I', hook, '1', '-j', chain);
			}
			rules.push('-F ' + chain, '-A ' + chain + ' ' + iface + ' lo -j RETURN');
			for (const other of WATCH[role]) {
				const addr = (await address(other))[name];
				if (addr) rules.push('-A ' + chain + ' ' + flag + ' ' + addr);
			}
			if (dropping.has(role)) rules.push('-A ' + chain + ' -j DROP');
		}
		// One commit replaces both chains, so nothing passes uncounted and an
		// outage begins and ends in both directions at once.
		rules.push('COMMIT', '');
		await restore(role, name + '-restore', rules.join('\n'));
	}
}
/** Cut a container off from everything but its own loopback, or reconnect it. */
async function outage(role, on) {
	if (on) dropping.add(role);
	else dropping.delete(role);
	await write(role);
}
/**
 * Packets between each watched pair since the rules were first written in
 * this run, as each end counted them: `out` to the other's address and `in`
 * from it.
 */
async function packets() {
	const all = {};
	for (const role of Object.keys(WATCH)) {
		const now = (await counted(role)) || {};
		all[role] = {};
		for (const other of WATCH[role]) {
			const before = carried[role]?.[other] || { out: 0, in: 0 };
			all[role][other] = {
				out: before.out + (now[other]?.out || 0),
				in: before.in + (now[other]?.in || 0)
			};
		}
	}
	return all;
}
/** Hold back everything a container sends by `ms`. Zero removes the hold. */
async function latency(role, ms) {
	await inspect(role);
	const tc = (...args) =>
		docker('exec', names[role], 'tc', 'qdisc', ...args, 'dev', 'eth0', 'root');
	if (ms > 0)
		await docker(
			'exec',
			names[role],
			'tc',
			'qdisc',
			'replace',
			'dev',
			'eth0',
			'root',
			'netem',
			'delay',
			ms + 'ms'
		);
	else
		await tc('del').catch((error) => {
			// Nothing to remove when no hold was set.
			if (!/Cannot delete qdisc|No such file|Invalid handle/.test(error.stderr))
				throw error;
		});
}
module.exports = {
	WATCH,
	address,
	addresses,
	begin,
	carry,
	write,
	outage,
	packets,
	latency
};
