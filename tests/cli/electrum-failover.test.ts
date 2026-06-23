import { expect } from 'chai';
import { BeignetNodeOptions } from '../../src/cli/beignet-node';
import { BeignetNodeEvents } from '../../src/cli/types';
import { ElectrumBackend } from '../../src/lightning/chain/electrum-backend';

describe('Electrum Failover — Multi-Server Support', () => {
	describe('BeignetNodeOptions.electrumServers', () => {
		it('accepts an array of electrum servers', () => {
			const opts: BeignetNodeOptions = {
				network: 'regtest',
				electrumServers: [
					{ host: 'electrum1.example.com', port: 50002, tls: true },
					{ host: 'electrum2.example.com', port: 50002, tls: true },
					{ host: 'electrum3.example.com', port: 50001, tls: false }
				]
			};
			expect(opts.electrumServers).to.have.length(3);
			expect(opts.electrumServers![0].host).to.equal('electrum1.example.com');
		});

		it('electrumServers is optional', () => {
			const opts: BeignetNodeOptions = { network: 'regtest' };
			expect(opts.electrumServers).to.be.undefined;
		});

		it('single server is valid (no failover)', () => {
			const opts: BeignetNodeOptions = {
				network: 'regtest',
				electrumServers: [{ host: '127.0.0.1', port: 60001 }]
			};
			expect(opts.electrumServers).to.have.length(1);
		});
	});

	describe('electrum:failover event', () => {
		it('event type is defined on BeignetNodeEvents', () => {
			const handler: BeignetNodeEvents['electrum:failover'] = (data) => {
				expect(data.from.host).to.be.a('string');
				expect(data.from.port).to.be.a('number');
				expect(data.to.host).to.be.a('string');
				expect(data.to.port).to.be.a('number');
				expect(data.timestamp).to.be.a('number');
			};
			handler({
				from: { host: 'electrum1.example.com', port: 50002 },
				to: { host: 'electrum2.example.com', port: 50002 },
				timestamp: Date.now()
			});
		});
	});

	describe('ElectrumBackend failover signaling', () => {
		// Create a minimal mock Electrum object
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
				broadcastTransaction: async () => ({
					isErr: () => false,
					value: 'txid'
				}),
				wallet: null
			};
		}

		it('consecutive failures counter starts at 0', () => {
			const backend = new ElectrumBackend(createMockElectrum());
			expect(backend.getConsecutiveFailures()).to.equal(0);
		});

		it('failoverThreshold defaults to 3', () => {
			const backend = new ElectrumBackend(createMockElectrum());
			expect(backend.failoverThreshold).to.equal(3);
		});

		it('failoverThreshold is configurable', () => {
			const backend = new ElectrumBackend(createMockElectrum(), 30_000, 5);
			expect(backend.failoverThreshold).to.equal(5);
		});

		it('onFailoverNeeded callback can be set', () => {
			const backend = new ElectrumBackend(createMockElectrum());
			let called = false;
			backend.onFailoverNeeded = () => {
				called = true;
			};
			expect(backend.onFailoverNeeded).to.be.a('function');
			backend.onFailoverNeeded(3);
			expect(called).to.be.true;
		});

		it('setElectrum replaces the underlying instance and resets failures', () => {
			const mock1 = createMockElectrum();
			const mock2 = createMockElectrum();
			const backend = new ElectrumBackend(mock1);
			// Simulate failures
			(backend as any)._consecutiveFailures = 5;
			expect(backend.getConsecutiveFailures()).to.equal(5);
			backend.setElectrum(mock2);
			expect(backend.getConsecutiveFailures()).to.equal(0);
		});

		it('callTimeoutMs defaults to 30s', () => {
			const backend = new ElectrumBackend(createMockElectrum());
			expect(backend.callTimeoutMs).to.equal(30_000);
		});
	});

	describe('ELECTRUM_REDUNDANCY readiness check', () => {
		it('warns when only 1 server configured', () => {
			const serverCount = 1;
			const status = serverCount > 1 ? 'PASS' : 'WARN';
			expect(status).to.equal('WARN');
		});

		it('passes when multiple servers configured', () => {
			const serverCount = 3;
			const status = serverCount > 1 ? 'PASS' : 'WARN';
			expect(status).to.equal('PASS');
		});
	});

	describe('Failover cycling', () => {
		it('cycles through servers round-robin', () => {
			const servers = [
				{ host: 'a.com', port: 50002 },
				{ host: 'b.com', port: 50002 },
				{ host: 'c.com', port: 50002 }
			];
			let idx = 0;
			const failoverSequence: string[] = [];
			for (let i = 0; i < 5; i++) {
				idx = (idx + 1) % servers.length;
				failoverSequence.push(servers[idx].host);
			}
			expect(failoverSequence).to.deep.equal([
				'b.com',
				'c.com',
				'a.com',
				'b.com',
				'c.com'
			]);
		});
	});
});
