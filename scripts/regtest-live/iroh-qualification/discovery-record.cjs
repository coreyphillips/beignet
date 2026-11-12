'use strict';
// What Iroh's discovery publishes for an endpoint.
//
// With the n0 preset an endpoint puts a signed record on n0's DNS server so
// that others can find it by its id. This binds two throwaway endpoints with
// fresh keys, one as Iroh binds by default and one with its UDP sockets on
// loopback as relay-only does, and reads each record back from that server
// three times over half a minute.
//
// Run it on the host, not in the fixture's containers: the case that matters
// is a network where the endpoint holds an address a stranger could route to,
// and a home network with port mapping is one. It prints kinds and counts and
// never an address.
//
// Exit 0: every record read carried no address. 1: one did. 2: no record
// could be read.
const crypto = require('crypto');
const iroh = require('@number0/iroh');

const SAMPLES_S = [6, 14, 30];
const ORIGIN = process.env.IROH_FORCE_STAGING_RELAYS
	? 'staging-dns.iroh.link'
	: 'dns.iroh.link';
const Z_BASE_32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';

function zBase32(bytes) {
	let bits = 0;
	let value = 0;
	let out = '';
	for (const byte of bytes) {
		value = ((value << 8) | byte) & 0xffff;
		bits += 8;
		while (bits >= 5) {
			out += Z_BASE_32[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0) out += Z_BASE_32[(value << (5 - bits)) & 31];
	return out;
}

/** True for an address only this host or this network can reach. */
function isLocal(host) {
	const h = host.replace(/^\[|\]$/g, '').toLowerCase();
	if (h.includes(':')) {
		return h === '::1' || /^fe[89ab]/.test(h) || /^f[cd]/.test(h);
	}
	const [a, b] = h.split('.').map(Number);
	return (
		a === 127 ||
		a === 10 ||
		(a === 192 && b === 168) ||
		(a === 172 && b >= 16 && b <= 31) ||
		(a === 169 && b === 254) ||
		(a === 100 && b >= 64 && b <= 127)
	);
}

/** The endpoint's record as n0's server holds it, read past every cache. */
async function readRecord(name) {
	const url = `https://${ORIGIN}/dns-query?name=${name}&type=TXT`;
	const res = await fetch(url, { headers: { accept: 'application/dns-json' } });
	if (!res.ok) return { error: `HTTP ${res.status}` };
	const body = await res.json();
	if (body.Status !== 0) return { error: `DNS status ${body.Status}` };
	const entries = (body.Answer ?? []).map((answer) =>
		String(answer.data).replace(/^"|"$/g, '')
	);
	const kinds = entries.map((entry) => entry.split('=')[0]);
	return {
		entries: entries.length,
		kinds: [...new Set(kinds)].sort(),
		addresses: kinds.filter((kind) => kind === 'addr').length
	};
}

async function observe(label, loopback) {
	const builder = iroh.Endpoint.builder();
	builder.applyN0();
	builder.secretKey(Array.from(crypto.randomBytes(32)));
	builder.alpns([]);
	if (loopback) {
		builder.bindAddr('127.0.0.1:0');
		builder.bindAddr('[::1]:0');
	}
	const endpoint = await builder.bind();
	await endpoint.online();
	const name = `_iroh.${zBase32(endpoint.id().toBytes())}.${ORIGIN}`;
	const started = Date.now();
	const samples = [];
	for (const atS of SAMPLES_S) {
		const wait = started + atS * 1000 - Date.now();
		if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
		const hosts = endpoint
			.addr()
			.directAddresses()
			.map((address) => address.replace(/:\d+$/, ''));
		samples.push({
			atS,
			endpointHolds: {
				addresses: hosts.length,
				routable: hosts.filter((host) => !isLocal(host)).length,
				relay: endpoint.addr().relayUrl() !== null
			},
			record: await readRecord(name).catch((error) => ({
				error: error.message
			}))
		});
	}
	await endpoint.close();
	return { label, samples };
}

async function main() {
	const results = [
		await observe('default', false),
		await observe('loopback-bound', true)
	];
	const records = results.flatMap((result) =>
		result.samples.map((sample) => sample.record)
	);
	const read = records.filter((record) => record.error === undefined);
	const leaked = read.filter((record) => record.addresses > 0).length;
	const routableHeld = results.some((result) =>
		result.samples.some((sample) => sample.endpointHolds.routable > 0)
	);
	console.log(
		JSON.stringify(
			{
				origin: ORIGIN,
				binding: require('@number0/iroh/package.json').version,
				results,
				recordsRead: read.length,
				recordsWithAnAddress: leaked,
				// Without this the run shows nothing: an endpoint that holds no
				// routable address has none to publish.
				anEndpointHeldARoutableAddress: routableHeld
			},
			null,
			'\t'
		)
	);
	process.exit(leaked > 0 ? 1 : read.length === 0 ? 2 : 0);
}

main().catch((error) => {
	console.error(error.message);
	process.exit(2);
});
