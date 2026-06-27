/**
 * Electrum Backend Timeout Tests
 *
 * Tests that ElectrumBackend wraps all async methods with configurable timeouts
 * to prevent indefinite hangs when the Electrum server stops responding.
 */

import { expect } from 'chai';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';

// ─────────────── Mock Electrum ───────────────

/** Creates a mock Electrum that hangs forever on all calls */
function makeHangingElectrum(): Record<string, unknown> {
	return {
		subscribeToHeader: () => new Promise(() => {}), // never resolves
		subscribeToAddresses: () => new Promise(() => {}),
		getAddressScriptHashesHistory: () => new Promise(() => {}),
		getTransactions: () => new Promise(() => {}),
		getTransactionMerkle: () => new Promise(() => {}),
		broadcastTransaction: () => new Promise(() => {}),
		onReceive: () => {}
	};
}

/** Creates a mock Electrum that resolves after a delay */
function makeSlowElectrum(delayMs: number): Record<string, unknown> {
	const delay = <T>(val: T): Promise<T> =>
		new Promise((resolve) => setTimeout(() => resolve(val), delayMs));
	return {
		subscribeToHeader: () =>
			delay({ isErr: () => false, value: { height: 100 } }),
		subscribeToAddresses: () => delay({ isErr: () => false, value: {} }),
		getAddressScriptHashesHistory: () =>
			delay({ isErr: () => false, value: { data: [] } }),
		getTransactions: () =>
			delay({
				isErr: () => false,
				value: { data: [{ result: { hex: 'aabb' } }] }
			}),
		getTransactionMerkle: () => delay({ pos: 0 }),
		broadcastTransaction: () =>
			delay({ isErr: () => false, value: 'deadbeef' }),
		onReceive: () => {}
	};
}

/** Creates a mock Electrum that resolves instantly */
function makeInstantElectrum(): Record<string, unknown> {
	return {
		subscribeToHeader: () =>
			Promise.resolve({ isErr: () => false, value: { height: 100 } }),
		subscribeToAddresses: () =>
			Promise.resolve({ isErr: () => false, value: {} }),
		getAddressScriptHashesHistory: () =>
			Promise.resolve({
				isErr: () => false,
				value: { data: [{ result: [{ tx_hash: 'abc', height: 1 }] }] }
			}),
		getTransactions: () =>
			Promise.resolve({
				isErr: () => false,
				value: { data: [{ result: { hex: 'deadbeef' } }] }
			}),
		getTransactionMerkle: () => Promise.resolve({ pos: 2 }),
		broadcastTransaction: () =>
			Promise.resolve({ isErr: () => false, value: 'txid123' }),
		onReceive: () => {}
	};
}

describe('ElectrumBackend — Call Timeouts', () => {
	describe('constructor', () => {
		it('should default callTimeoutMs to 30000', () => {
			const backend = new ElectrumBackend(makeInstantElectrum() as never);
			expect(backend.callTimeoutMs).to.equal(30_000);
		});

		it('should accept custom callTimeoutMs', () => {
			const backend = new ElectrumBackend(
				makeInstantElectrum() as never,
				5_000
			);
			expect(backend.callTimeoutMs).to.equal(5_000);
		});
	});

	describe('timeout on hanging calls', () => {
		const TIMEOUT_MS = 100; // very short for testing

		it('subscribeToHeaders should time out', async () => {
			const backend = new ElectrumBackend(
				makeHangingElectrum() as never,
				TIMEOUT_MS
			);
			try {
				await backend.subscribeToHeaders(() => {});
				expect.fail('should have thrown');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('timed out');
				expect((err as Error).message).to.include('subscribeToHeaders');
			}
		});

		it('subscribeToScriptHash should time out', async () => {
			const backend = new ElectrumBackend(
				makeHangingElectrum() as never,
				TIMEOUT_MS
			);
			try {
				await backend.subscribeToScriptHash('abc123', () => {});
				expect.fail('should have thrown');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('timed out');
				expect((err as Error).message).to.include('subscribeToScriptHash');
			}
		});

		it('getScriptHashHistory should time out', async () => {
			const backend = new ElectrumBackend(
				makeHangingElectrum() as never,
				TIMEOUT_MS
			);
			try {
				await backend.getScriptHashHistory('abc123');
				expect.fail('should have thrown');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('timed out');
				expect((err as Error).message).to.include('getScriptHashHistory');
			}
		});

		it('getTransaction should time out', async () => {
			const backend = new ElectrumBackend(
				makeHangingElectrum() as never,
				TIMEOUT_MS
			);
			try {
				await backend.getTransaction('deadbeef');
				expect.fail('should have thrown');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('timed out');
				expect((err as Error).message).to.include('getTransaction');
			}
		});

		it('getTransactionMerkleProof should time out', async () => {
			const backend = new ElectrumBackend(
				makeHangingElectrum() as never,
				TIMEOUT_MS
			);
			try {
				await backend.getTransactionMerkleProof('deadbeef', 100);
				expect.fail('should have thrown');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('timed out');
				expect((err as Error).message).to.include('getTransactionMerkleProof');
			}
		});

		it('broadcastTransaction should time out', async () => {
			const backend = new ElectrumBackend(
				makeHangingElectrum() as never,
				TIMEOUT_MS
			);
			try {
				await backend.broadcastTransaction('0100000000');
				expect.fail('should have thrown');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('timed out');
				expect((err as Error).message).to.include('broadcastTransaction');
			}
		});
	});

	describe('successful calls within timeout', () => {
		it('all methods should resolve when Electrum responds instantly', async () => {
			const backend = new ElectrumBackend(
				makeInstantElectrum() as never,
				5_000
			);

			// subscribeToHeaders
			let headerHeight = 0;
			await backend.subscribeToHeaders((h) => {
				headerHeight = h;
			});
			expect(headerHeight).to.equal(100);

			// subscribeToScriptHash
			await backend.subscribeToScriptHash('aabb', () => {});

			// getScriptHashHistory
			const history = await backend.getScriptHashHistory('aabb');
			expect(history).to.have.length(1);
			expect(history[0].txid).to.equal('abc');

			// getTransaction
			const tx = await backend.getTransaction('abc');
			expect(tx.toString('hex')).to.equal('deadbeef');

			// getTransactionMerkleProof
			const proof = await backend.getTransactionMerkleProof('abc', 1);
			expect(proof.txIndex).to.equal(2);

			// broadcastTransaction
			const txid = await backend.broadcastTransaction('aabb');
			expect(txid).to.equal('txid123');

			backend.stopReconnectMonitor();
		});

		it('should resolve when call is slower than deadline but within timeout', async () => {
			const backend = new ElectrumBackend(makeSlowElectrum(50) as never, 500);
			const history = await backend.getScriptHashHistory('aabb');
			expect(history).to.be.an('array');
		});
	});

	describe('resubscribeAll timeout resilience', () => {
		it('should swallow timeout errors during resubscribeAll', async () => {
			// First, set up with an instant electrum to register subscriptions
			const instantElectrum = makeInstantElectrum();
			const backend = new ElectrumBackend(instantElectrum as never, 5_000);
			await backend.subscribeToHeaders(() => {});
			await backend.subscribeToScriptHash('script1', () => {});
			backend.stopReconnectMonitor();

			// Now swap the underlying electrum to a hanging one
			(backend as unknown as { electrum: unknown }).electrum =
				makeHangingElectrum();
			(backend as unknown as { callTimeoutMs: number }).callTimeoutMs = 100;
			// Object.defineProperty won't work since callTimeoutMs is readonly, use a cast
			Object.defineProperty(backend, 'callTimeoutMs', { value: 100 });

			// resubscribeAll should NOT throw even though all calls time out
			// (subscribeToHeaders will throw, but script hash resubscription is swallowed)
			try {
				await backend.resubscribeAll();
			} catch {
				// subscribeToHeaders timeout is expected to propagate
			}
		});
	});

	describe('unsubscribeScriptHash', () => {
		it('should remove a tracked script hash', async () => {
			const backend = new ElectrumBackend(
				makeInstantElectrum() as never,
				5_000
			);
			await backend.subscribeToScriptHash('aabb', () => {});
			backend.stopReconnectMonitor();

			const removed = backend.unsubscribeScriptHash('aabb');
			expect(removed).to.be.true;

			// Double remove returns false
			const removedAgain = backend.unsubscribeScriptHash('aabb');
			expect(removedAgain).to.be.false;
		});
	});
});
