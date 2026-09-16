import * as net from 'net';
import * as tls from 'tls';

import { EProtocol } from '../src';

/**
 * Is any of these Electrum servers actually answering?
 *
 * The on-chain wallet suites talk to public Electrum servers over the
 * internet, so an outage at the far end failed them in a way that looked
 * like a code fault: every `before` hook hit its 60s timeout after
 * "Connection to server lost, please retry", and which suites failed
 * changed from run to run. That is a PR-gating job reporting someone
 * else's downtime, and the noise trains people to ignore it.
 *
 * The interop suites already skip rather than fail when the thing they
 * need is not there. This is the same idea for the one dependency these
 * suites cannot bring up themselves. A skip is honest: it says the
 * behaviour was not checked, where a red X says it was checked and is
 * broken.
 *
 * It speaks the protocol rather than testing for an open port, because a
 * server that accepts a connection and then answers nothing is exactly
 * the failure being guarded against.
 */
interface IProbeServer {
	host: string;
	ssl: number;
	tcp: number;
	protocol: EProtocol;
}

const REQUEST =
	JSON.stringify({
		id: 0,
		method: 'server.version',
		params: ['beignet-tests', '1.4']
	}) + '\n';

function probe(server: IProbeServer, timeoutMs: number): Promise<boolean> {
	return new Promise((resolve) => {
		const useTls = server.protocol === EProtocol.ssl;
		const port = useTls ? server.ssl : server.tcp;
		let settled = false;
		const done = (ok: boolean): void => {
			if (settled) return;
			settled = true;
			try {
				socket.destroy();
			} catch {
				// Already gone; the answer is what matters.
			}
			resolve(ok);
		};

		const socket = useTls
			? tls.connect({
					host: server.host,
					port,
					// Public Electrum servers commonly present a self signed
					// certificate, and this is a liveness probe, not a trust
					// decision: nothing it learns is used as data.
					rejectUnauthorized: false
			  })
			: net.connect({ host: server.host, port });

		let buffer = '';
		socket.setTimeout(timeoutMs);
		socket.on(useTls ? 'secureConnect' : 'connect', () =>
			socket.write(REQUEST)
		);
		socket.on('data', (chunk: Buffer) => {
			buffer += chunk.toString('utf8');
			if (!buffer.includes('\n')) return;
			try {
				done(JSON.parse(buffer.split('\n')[0]).result !== undefined);
			} catch {
				done(false);
			}
		});
		socket.on('timeout', () => done(false));
		socket.on('error', () => done(false));
		socket.on('close', () => done(false));
	});
}

/** True when at least one server answered server.version in time. */
export async function anyElectrumReachable(
	list: IProbeServer[],
	timeoutMs = 5000
): Promise<boolean> {
	for (const server of list ?? []) {
		if (await probe(server, timeoutMs)) return true;
	}
	return false;
}

/**
 * Skip the calling suite when no server answers. Call it first in a
 * `before` hook, which must be a `function` rather than an arrow so that
 * `this.skip()` reaches Mocha's context.
 */
export async function skipWithoutElectrum(
	ctx: Mocha.Context,
	list: IProbeServer[],
	label = 'Electrum'
): Promise<void> {
	if (await anyElectrumReachable(list)) return;
	const where = (list ?? []).map((s) => s.host).join(', ') || 'none configured';
	console.log(
		`    skipping: no ${label} server answered (${where}). ` +
			'These suites need a reachable Electrum server.'
	);
	ctx.skip();
}

/**
 * Run the wallet's first refresh under a deadline, and skip the suite if it
 * does not finish.
 *
 * Reachability alone is not enough. The public server answers
 * `server.version`, `blockchain.headers.subscribe` and a scripthash balance
 * on a fresh socket and still takes wildly different times to serve a whole
 * refresh. Seven consecutive runs of this wallet, same code, same machine,
 * same server: 17.6s, 24.7s, 43.8s, 43.9s, 47.7s, 81.7s, 89.1s. Every one
 * completed. The refresh is roughly 200 requests, each individually bounded
 * by rn-electrum-client's own timeouts, and the spread is the server's
 * throughput on the day rather than anything this code does.
 *
 * So the budget has to sit above the slow tail, not in the middle of it: a
 * 60s hook against a distribution whose median is in the forties is a coin
 * flip, which is what made the old failures come and go between identical
 * runs. 120s clears every run observed, with headroom.
 *
 * The deadline exists for the case where the server genuinely cannot serve
 * the suite at all. Then a skip says more than a red X: it reports that the
 * behaviour was not checked, rather than that it was checked and is broken.
 *
 * The refresh is left running rather than cancelled; the suite's `after`
 * hook disconnects, and nothing downstream reads its result.
 */
export async function refreshOrSkip(
	ctx: Mocha.Context,
	wallet: { refreshWallet: (arg?: object) => Promise<unknown> },
	budgetMs = 120_000
): Promise<void> {
	// Mocha's own timeout has to outlast the budget, or the hook fails at 60s
	// before this can decide anything.
	ctx.timeout(budgetMs + 30_000);
	let timer: NodeJS.Timeout | undefined;
	const deadline = new Promise<'timeout'>((resolve) => {
		timer = setTimeout(() => resolve('timeout'), budgetMs);
		// Do not hold the process open on account of the deadline itself.
		timer.unref?.();
	});
	const outcome = await Promise.race([
		wallet.refreshWallet({}).then(() => 'done' as const),
		deadline
	]);
	if (timer) clearTimeout(timer);
	if (outcome === 'done') return;
	console.log(
		`    skipping: the first wallet refresh did not finish within ${
			budgetMs / 1000
		}s. The Electrum server answered but could not serve a full refresh.`
	);
	ctx.skip();
}
