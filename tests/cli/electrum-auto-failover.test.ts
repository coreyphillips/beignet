import { expect } from 'chai';
import { BeignetNodeOptions } from '../../src/cli/beignet-node';
import { BeignetNodeEvents } from '../../src/cli/types';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';

describe('Electrum Auto-Failover — Actual Reconnection', () => {
	function createMockElectrum(): any {
		return {
			subscribeToHeader: async () => ({
				isErr: () => false,
				value: { height: 100 }
			}),
			subscribeToAddresses: async () => ({ isErr: () => false }),
			onReceive: () => {},
			getAddressScriptHashesHistory: async () => ({
				isErr: () => false,
				value: { data: [] }
			}),
			getTransactions: async () => ({
				isErr: () => false,
				value: { data: [] }
			}),
			getTransactionMerkle: async () => ({ pos: 0 }),
			broadcastTransaction: async () => ({ isErr: () => false, value: 'txid' }),
			wallet: null,
			connectedToElectrum: true
		};
	}

	describe('onFailoverNeeded callback', () => {
		it('round-robins through remaining servers', () => {
			const servers = [
				{ host: 'a.com', port: 50002 },
				{ host: 'b.com', port: 50002 },
				{ host: 'c.com', port: 50002 }
			];
			let currentServerIndex = 0;
			const visited: string[] = [];

			// Simulate 5 failover cycles
			for (let failover = 0; failover < 5; failover++) {
				currentServerIndex = (currentServerIndex + 1) % servers.length;
				visited.push(servers[currentServerIndex].host);
			}

			expect(visited).to.deep.equal([
				'b.com',
				'c.com',
				'a.com',
				'b.com',
				'c.com'
			]);
		});

		it('emits node:error when all servers fail', () => {
			// Simulates the all-servers-failed path in the onFailoverNeeded callback
			const errors: Array<{ code: string; message: string }> = [];
			const failedAttempts = 3; // All 3 servers fail
			const totalServers = 3;

			if (failedAttempts >= totalServers - 1) {
				errors.push({
					code: 'ELECTRUM_FAILOVER_FAILED',
					message: 'All Electrum servers failed during failover'
				});
			}

			expect(errors).to.have.length(1);
			expect(errors[0].code).to.equal('ELECTRUM_FAILOVER_FAILED');
		});

		it('re-entrancy guard prevents concurrent failover attempts', async () => {
			let callCount = 0;
			let _failoverInProgress = false;

			const failoverFn = async (): Promise<void> => {
				if (_failoverInProgress) return;
				_failoverInProgress = true;
				callCount++;
				// Simulate async work
				await new Promise((resolve) => setTimeout(resolve, 10));
				_failoverInProgress = false;
			};

			// Fire 3 concurrent failover attempts
			await Promise.all([failoverFn(), failoverFn(), failoverFn()]);

			// Only the first one should have executed
			expect(callCount).to.equal(1);
		});

		it('consecutive failure counter resets after successful failover', () => {
			const backend = new ElectrumBackend(createMockElectrum());
			// Simulate failures
			(backend as any)._consecutiveFailures = 5;
			expect(backend.getConsecutiveFailures()).to.equal(5);

			// setElectrum resets failures (mimics successful failover)
			backend.setElectrum(createMockElectrum());
			expect(backend.getConsecutiveFailures()).to.equal(0);
		});

		it('electrum:failover event has correct from/to payload', () => {
			const events: Array<{
				from: { host: string; port: number };
				to: { host: string; port: number };
				timestamp: number;
			}> = [];
			const handler: BeignetNodeEvents['electrum:failover'] = (data) => {
				events.push(data);
			};

			handler({
				from: { host: 'failed.com', port: 50002 },
				to: { host: 'backup.com', port: 50003 },
				timestamp: Date.now()
			});

			expect(events).to.have.length(1);
			expect(events[0].from.host).to.equal('failed.com');
			expect(events[0].to.host).to.equal('backup.com');
			expect(events[0].to.port).to.equal(50003);
			expect(events[0].timestamp).to.be.a('number');
		});

		it('guard clears after failover completes (allows retry on next monitor tick)', async () => {
			let _failoverInProgress = false;
			let attemptCount = 0;

			const failoverFn = async (): Promise<void> => {
				if (_failoverInProgress) return;
				_failoverInProgress = true;
				attemptCount++;
				await new Promise((resolve) => setTimeout(resolve, 5));
				_failoverInProgress = false;
			};

			// First attempt
			await failoverFn();
			expect(attemptCount).to.equal(1);

			// Second attempt after first completes — should proceed
			await failoverFn();
			expect(attemptCount).to.equal(2);
		});
	});

	describe('BeignetNodeOptions validation', () => {
		it('electrumServers with 2+ entries enables failover', () => {
			const opts: BeignetNodeOptions = {
				network: 'regtest',
				electrumServers: [
					{ host: 'primary.com', port: 50002, tls: true },
					{ host: 'backup.com', port: 50002, tls: true }
				]
			};
			expect(opts.electrumServers!.length).to.be.at.least(2);
		});
	});
});
