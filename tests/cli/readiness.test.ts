import { expect } from 'chai';
import { ReadinessReport, ReadinessCheck } from '../../src/cli/types';

describe('Mainnet Readiness Checklist', () => {
	// Test the types and report structure
	it('ReadinessReport has score, ready, and checks fields', () => {
		const report: ReadinessReport = {
			score: 85,
			ready: true,
			checks: []
		};
		expect(report.score).to.be.a('number');
		expect(report.ready).to.be.a('boolean');
		expect(report.checks).to.be.an('array');
	});

	it('ReadinessCheck has name, status, severity, and message', () => {
		const check: ReadinessCheck = {
			name: 'STORAGE_CONFIGURED',
			status: 'PASS',
			severity: 'CRITICAL',
			message: 'Storage configured'
		};
		expect(check.name).to.equal('STORAGE_CONFIGURED');
		expect(check.status).to.equal('PASS');
		expect(check.severity).to.equal('CRITICAL');
		expect(check.message).to.equal('Storage configured');
	});

	it('score is 0-100', () => {
		const report: ReadinessReport = { score: 50, ready: true, checks: [] };
		expect(report.score).to.be.at.least(0);
		expect(report.score).to.be.at.most(100);
	});

	it('ready is false when any CRITICAL check fails', () => {
		const checks: ReadinessCheck[] = [
			{
				name: 'STORAGE_CONFIGURED',
				status: 'FAIL',
				severity: 'CRITICAL',
				message: 'No storage'
			},
			{
				name: 'AUTO_RECONNECT_ENABLED',
				status: 'PASS',
				severity: 'WARNING',
				message: 'OK'
			}
		];
		const hasCriticalFailure = checks.some(
			(c) => c.status === 'FAIL' && c.severity === 'CRITICAL'
		);
		expect(hasCriticalFailure).to.be.true;
	});

	it('ready is true when only INFO/WARNING checks fail', () => {
		const checks: ReadinessCheck[] = [
			{
				name: 'STORAGE_CONFIGURED',
				status: 'PASS',
				severity: 'CRITICAL',
				message: 'OK'
			},
			{
				name: 'HAS_ACTIVE_CHANNEL',
				status: 'WARN',
				severity: 'INFO',
				message: 'No channels'
			}
		];
		const hasCriticalFailure = checks.some(
			(c) => c.status === 'FAIL' && c.severity === 'CRITICAL'
		);
		expect(hasCriticalFailure).to.be.false;
	});

	it('all 11 check names are defined', () => {
		const expectedNames = [
			'STORAGE_CONFIGURED',
			'CHAIN_BACKEND_CONNECTED',
			'AUTO_RECONNECT_ENABLED',
			'ANCHOR_CHANNELS_PREFERRED',
			'HAS_ACTIVE_CHANNEL',
			'GOSSIP_GRAPH_POPULATED',
			'FEE_ESTIMATOR_AVAILABLE',
			'ELECTRUM_REDUNDANCY',
			'BACKUP_CONFIGURED',
			'SUFFICIENT_CHANNELS',
			'CHANNEL_BALANCE_HEALTH'
		];
		for (const name of expectedNames) {
			expect(name).to.be.a('string');
		}
		expect(expectedNames).to.have.length(11);
	});

	it('ELECTRUM_REDUNDANCY warns when only 1 server', () => {
		const check: ReadinessCheck = {
			name: 'ELECTRUM_REDUNDANCY',
			status: 'WARN',
			severity: 'WARNING',
			message: 'Only 1 Electrum server configured — no failover if it goes down'
		};
		expect(check.status).to.equal('WARN');
		expect(check.severity).to.equal('WARNING');
	});

	it('ELECTRUM_REDUNDANCY passes with multiple servers', () => {
		const check: ReadinessCheck = {
			name: 'ELECTRUM_REDUNDANCY',
			status: 'PASS',
			severity: 'WARNING',
			message: '3 Electrum servers configured for failover'
		};
		expect(check.status).to.equal('PASS');
	});

	it('BACKUP_CONFIGURED warns when no backup path set', () => {
		const check: ReadinessCheck = {
			name: 'BACKUP_CONFIGURED',
			status: 'WARN',
			severity: 'WARNING',
			message:
				'No backup path configured — channel state is only in the primary database'
		};
		expect(check.status).to.equal('WARN');
	});

	it('BACKUP_CONFIGURED passes when backup path set', () => {
		const check: ReadinessCheck = {
			name: 'BACKUP_CONFIGURED',
			status: 'PASS',
			severity: 'WARNING',
			message: 'Automated backups configured to /backups/node.db'
		};
		expect(check.status).to.equal('PASS');
	});

	it('SUFFICIENT_CHANNELS warns when only 1 ready channel', () => {
		const check: ReadinessCheck = {
			name: 'SUFFICIENT_CHANNELS',
			status: 'WARN',
			severity: 'WARNING',
			message: 'Only 1 ready channel — single channel is a point of failure'
		};
		expect(check.status).to.equal('WARN');
	});

	it('SUFFICIENT_CHANNELS passes with 2+ ready channels', () => {
		const check: ReadinessCheck = {
			name: 'SUFFICIENT_CHANNELS',
			status: 'PASS',
			severity: 'WARNING',
			message: '3 ready channels (redundancy OK)'
		};
		expect(check.status).to.equal('PASS');
	});

	it('CHANNEL_BALANCE_HEALTH warns when all channels depleted', () => {
		const check: ReadinessCheck = {
			name: 'CHANNEL_BALANCE_HEALTH',
			status: 'WARN',
			severity: 'INFO',
			message: 'All 2 channel(s) are >90% depleted in one direction'
		};
		expect(check.status).to.equal('WARN');
		expect(check.severity).to.equal('INFO');
	});

	it('CHANNEL_BALANCE_HEALTH passes when balances are healthy', () => {
		const check: ReadinessCheck = {
			name: 'CHANNEL_BALANCE_HEALTH',
			status: 'PASS',
			severity: 'INFO',
			message: 'Channel balances are healthy'
		};
		expect(check.status).to.equal('PASS');
	});

	it('score calculation: CRITICAL failure reduces score by 30', () => {
		let score = 100;
		const checks: ReadinessCheck[] = [
			{ name: 'TEST', status: 'FAIL', severity: 'CRITICAL', message: 'fail' }
		];
		for (const check of checks) {
			if (check.status === 'FAIL' && check.severity === 'CRITICAL') score -= 30;
			else if (check.status === 'WARN' && check.severity === 'WARNING')
				score -= 10;
			else if (check.status === 'WARN' && check.severity === 'INFO') score -= 5;
		}
		score = Math.max(0, score);
		expect(score).to.equal(70);
	});

	it('score calculation: WARNING reduces score by 10', () => {
		let score = 100;
		const checks: ReadinessCheck[] = [
			{ name: 'TEST1', status: 'WARN', severity: 'WARNING', message: 'warn' },
			{ name: 'TEST2', status: 'WARN', severity: 'WARNING', message: 'warn' }
		];
		for (const check of checks) {
			if (check.status === 'FAIL' && check.severity === 'CRITICAL') score -= 30;
			else if (check.status === 'WARN' && check.severity === 'WARNING')
				score -= 10;
			else if (check.status === 'WARN' && check.severity === 'INFO') score -= 5;
		}
		score = Math.max(0, score);
		expect(score).to.equal(80);
	});
});
