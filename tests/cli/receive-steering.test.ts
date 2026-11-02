/**
 * The candidate walk behind a steered receive (issue #1922, step 2a): one
 * budget over the whole list, short caps while more candidates remain, the
 * last one gets the remainder, a candidate's own failure moves on and any
 * other failure ends the walk, and the typed answer when none takes it.
 */

import { expect } from 'chai';
import { BeignetError, isRetryableError } from '../../src/cli/errors';
import { statusForErrorCode } from '../../src/cli/daemon';
import {
	JIT_STEER_CODES,
	STEER_ATTEMPT_CAP_MS,
	STEER_BUDGET_CODE,
	STEER_BUDGET_MS,
	STEER_CONNECT_CAP_MS,
	dialTargetOf,
	steerReceive
} from '../../src/cli/receive-steering';
import type {
	ISteerCandidate,
	ISteerSkip
} from '../../src/cli/receive-steering';

const A = '02' + 'aa'.repeat(32);
const B = '03' + 'bb'.repeat(32);
const C = '02' + 'cc'.repeat(32);

function candidates(...pubkeys: string[]): ISteerCandidate[] {
	return pubkeys.map((pubkey, i) => ({ pubkey, rank: i + 1, balanceSat: 0 }));
}

/** A clock the attempts move by hand. */
function clock(): { now: () => number; tick: (ms: number) => void } {
	let t = 1_000_000;
	return { now: (): number => t, tick: (ms): void => void (t += ms) };
}

const refused = (message: string): BeignetError =>
	new BeignetError('JIT_REFUSED', message);

describe('steerReceive (issue #1922)', () => {
	it('takes the first candidate that is connected and accepts', async () => {
		const tried: string[] = [];
		const result = await steerReceive({
			candidates: candidates(A, B),
			isConnected: () => true,
			attempt: async (c) => {
				tried.push(c.pubkey);
				return `invoice@${c.pubkey}`;
			},
			candidateCodes: JIT_STEER_CODES
		});
		expect(result).to.deep.equal({
			value: `invoice@${A}`,
			pubkey: A,
			skipped: []
		});
		expect(tried).to.deep.equal([A]);
	});

	it('dials a candidate that is not connected, and skips it when the dial fails', async () => {
		const dialed: Array<[string, number]> = [];
		const result = await steerReceive({
			candidates: candidates(A, B),
			isConnected: (pubkey) => pubkey === B,
			connect: async (c, timeoutMs) => {
				dialed.push([c.pubkey, timeoutMs]);
				throw new BeignetError('CONNECT_FAILED', 'ECONNREFUSED');
			},
			attempt: async (c) => c.pubkey,
			candidateCodes: JIT_STEER_CODES
		});
		expect(result.pubkey).to.equal(B);
		// While another candidate remains, a dial gets the short cap.
		expect(dialed).to.deep.equal([[A, STEER_CONNECT_CAP_MS]]);
		expect(result.skipped).to.deep.equal([
			{
				pubkey: A,
				rank: 1,
				stage: 'connect',
				code: 'CONNECT_FAILED',
				message: 'ECONNREFUSED'
			}
		]);
	});

	it('skips a disconnected candidate outright when the caller never dials', async () => {
		const result = await steerReceive({
			candidates: candidates(A, B),
			isConnected: (pubkey) => pubkey === B,
			attempt: async (c) => c.pubkey,
			candidateCodes: JIT_STEER_CODES
		});
		expect(result.pubkey).to.equal(B);
		expect(result.skipped[0]).to.include({
			pubkey: A,
			stage: 'connect',
			code: 'PEER_NOT_CONNECTED'
		});
	});

	it('moves past a decline and reports it, in order', async () => {
		const seen: ISteerSkip[] = [];
		const result = await steerReceive({
			candidates: candidates(A, B, C),
			isConnected: () => true,
			attempt: async (c) => {
				if (c.pubkey !== C) throw refused(`${c.rank} says no`);
				return 'ok';
			},
			candidateCodes: JIT_STEER_CODES,
			onSkip: (s) => seen.push(s)
		});
		expect(result.pubkey).to.equal(C);
		expect(
			result.skipped.map((s) => [s.pubkey, s.code, s.message])
		).to.deep.equal([
			[A, 'JIT_REFUSED', '1 says no'],
			[B, 'JIT_REFUSED', '2 says no']
		]);
		expect(seen).to.deep.equal(result.skipped);
	});

	it('caps an attempt short while more remain and gives the last the remainder', async () => {
		const { now, tick } = clock();
		const caps: number[] = [];
		const result = await steerReceive({
			candidates: candidates(A, B),
			isConnected: () => true,
			attempt: async (c, timeoutMs) => {
				caps.push(timeoutMs);
				if (c.pubkey === A) {
					// The first eats its whole cap and times out.
					tick(timeoutMs);
					throw new BeignetError('JIT_TIMEOUT', 'no ack');
				}
				return 'ok';
			},
			candidateCodes: JIT_STEER_CODES,
			now
		});
		expect(result.pubkey).to.equal(B);
		expect(caps).to.deep.equal([
			STEER_ATTEMPT_CAP_MS,
			STEER_BUDGET_MS - STEER_ATTEMPT_CAP_MS
		]);
	});

	it('honours the last-candidate caps a caller sets', async () => {
		const { now } = clock();
		const caps: Array<[string, number]> = [];
		await steerReceive({
			candidates: candidates(A),
			isConnected: () => false,
			connect: async (c, timeoutMs) => {
				caps.push(['connect', timeoutMs]);
			},
			attempt: async (c, timeoutMs) => {
				caps.push(['attempt', timeoutMs]);
				return 'ok';
			},
			candidateCodes: JIT_STEER_CODES,
			now,
			lastConnectCapMs: 1_500,
			lastAttemptCapMs: 15_000
		});
		expect(caps).to.deep.equal([
			['connect', 1_500],
			['attempt', 15_000]
		]);
	});

	it('stops when the budget runs out and lists the candidates it never reached', async () => {
		const { now, tick } = clock();
		const tried: string[] = [];
		let error: unknown;
		try {
			await steerReceive({
				candidates: candidates(A, B, C),
				isConnected: () => true,
				attempt: async (c, timeoutMs) => {
					tried.push(c.pubkey);
					tick(timeoutMs);
					throw new BeignetError('JIT_TIMEOUT', 'no ack');
				},
				candidateCodes: JIT_STEER_CODES,
				budgetMs: 10_000,
				attemptCapMs: 6_000,
				floorMs: 5_000,
				now
			});
		} catch (e) {
			error = e;
		}
		// A took 6 s, leaving 4 s: under the 5 s floor, so B and C are not tried.
		expect(tried).to.deep.equal([A]);
		expect(error).to.be.instanceOf(BeignetError);
		const err = error as BeignetError;
		expect(err.code).to.equal('NO_PRIMARY_AVAILABLE');
		expect(err.message).to.match(
			/^No primary could take the receive \(1 of 3 tried\)/
		);
		expect(err.message).to.include(
			`${A.slice(0, 16)} (rank 1): JIT_TIMEOUT no ack`
		);
		expect(err.message).to.include(
			`${B.slice(0, 16)} (rank 2): ${STEER_BUDGET_CODE}`
		);
		expect(err.message).to.include(
			`${C.slice(0, 16)} (rank 3): ${STEER_BUDGET_CODE}`
		);
	});

	it('answers NO_PRIMARY_AVAILABLE naming every reason when none takes it', async () => {
		let error: unknown;
		try {
			await steerReceive({
				candidates: candidates(A, B),
				isConnected: (pubkey) => pubkey === B,
				attempt: async () => {
					throw refused('declined: max fundable is 1000 sats');
				},
				candidateCodes: JIT_STEER_CODES
			});
		} catch (e) {
			error = e;
		}
		const err = error as BeignetError;
		expect(err.code).to.equal('NO_PRIMARY_AVAILABLE');
		// A candidate the walk reached counts as tried, connected or not; only
		// one the budget never got to does not.
		expect(err.message).to.include('(2 of 2 tried)');
		expect(err.message).to.include('PEER_NOT_CONNECTED not connected');
		expect(err.message).to.include(
			'JIT_REFUSED declined: max fundable is 1000 sats'
		);
		// The daemon says retry: every primary was down or declining at once.
		expect(statusForErrorCode(err.code)).to.equal(503);
		expect(isRetryableError(err)).to.equal(true);
	});

	it("rethrows a failure that is not one candidate's own and ends the walk", async () => {
		const tried: string[] = [];
		let error: unknown;
		try {
			await steerReceive({
				candidates: candidates(A, B),
				isConnected: () => true,
				attempt: async (c) => {
					tried.push(c.pubkey);
					throw new BeignetError(
						'INVALID_PARAMS',
						'amountSats must be a whole number'
					);
				},
				candidateCodes: JIT_STEER_CODES
			});
		} catch (e) {
			error = e;
		}
		expect((error as BeignetError).code).to.equal('INVALID_PARAMS');
		expect(tried).to.deep.equal([A]);
	});

	it('rethrows a plain fault from a dial, but skips a typed one', async () => {
		let error: unknown;
		try {
			await steerReceive({
				candidates: candidates(A, B),
				isConnected: () => false,
				connect: async () => {
					throw new TypeError('peerManager.connectPeer is not a function');
				},
				attempt: async () => 'ok',
				candidateCodes: JIT_STEER_CODES
			});
		} catch (e) {
			error = e;
		}
		expect(error).to.be.instanceOf(TypeError);

		// Iroh not enabled is INVALID_PARAMS from the dial: this peer's own
		// problem, not the caller's request.
		const result = await steerReceive({
			candidates: candidates(A, B),
			isConnected: (pubkey) => pubkey === B,
			connect: async () => {
				throw new BeignetError(
					'INVALID_PARAMS',
					'Iroh transport is not enabled'
				);
			},
			attempt: async (c) => c.pubkey,
			candidateCodes: JIT_STEER_CODES
		});
		expect(result.pubkey).to.equal(B);
		expect(result.skipped[0]).to.include({
			stage: 'connect',
			code: 'INVALID_PARAMS'
		});
	});

	it('refuses an empty list as INVALID_PARAMS', async () => {
		let error: unknown;
		try {
			await steerReceive({
				candidates: [],
				isConnected: () => true,
				attempt: async () => 'ok',
				candidateCodes: JIT_STEER_CODES
			});
		} catch (e) {
			error = e;
		}
		expect((error as BeignetError).code).to.equal('INVALID_PARAMS');
	});
});

describe('dialTargetOf', () => {
	const base = { pubkey: A, rank: 1, balanceSat: 0 };

	it('passes a host and port through as a TCP dial', () => {
		expect(
			dialTargetOf({ ...base, host: '10.0.0.2', port: 9735 })
		).to.deep.equal({ host: '10.0.0.2', port: 9735 });
	});

	it('turns a ws URI into the WebSocket transport', () => {
		expect(
			dialTargetOf({ ...base, uri: `${A}@wss://lsp.example:443` })
		).to.deep.equal({
			host: 'lsp.example',
			port: 443,
			transport: { type: 'ws', url: 'wss://lsp.example:443' }
		});
	});

	it('turns an iroh URI into the Iroh transport', () => {
		const endpoint = 'ab'.repeat(32);
		const target = dialTargetOf({ ...base, uri: `${A}@iroh:${endpoint}` });
		expect(target.port).to.equal(0);
		expect(target.transport?.type).to.equal('iroh');
		expect(target.transport?.endpointId).to.be.a('string');
	});

	it('leaves the address to the library when nothing is stored', () => {
		expect(dialTargetOf(base)).to.deep.equal({});
	});
});
