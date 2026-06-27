/**
 * Typed Events Tests
 *
 * Verifies BeignetNode's typed event overloads work correctly.
 */

import { expect } from 'chai';
import { BeignetNodeEvents, PaymentInfo } from '../../src/cli/types';

describe('BeignetNodeEvents', () => {
	it('should include all expected event names', () => {
		// Compile-time type check: all event names exist on the interface
		const events: Array<keyof BeignetNodeEvents> = [
			'payment:received',
			'payment:sent',
			'payment:failed',
			'channel:ready',
			'channel:closed',
			'peer:connect',
			'peer:disconnect',
			'node:error',
			'log'
		];
		expect(events).to.have.length(9);
	});

	it('log event type should include level, message, timestamp', () => {
		// Type-level test: ensure log event has the right shape
		const handler: BeignetNodeEvents['log'] = (entry) => {
			expect(entry).to.have.property('level');
			expect(entry).to.have.property('message');
			expect(entry).to.have.property('timestamp');
		};
		handler({ level: 'info', message: 'test', timestamp: Date.now() });
	});

	it('payment events should receive PaymentInfo', () => {
		const handler: BeignetNodeEvents['payment:received'] = (
			info: PaymentInfo
		) => {
			expect(info).to.have.property('paymentHash');
			expect(info).to.have.property('status');
		};
		handler({
			paymentHash: 'abc',
			amountSats: 100,
			status: 'COMPLETED',
			direction: 'INCOMING',
			createdAt: Date.now()
		});
	});

	it('channel events should receive channelId', () => {
		const handler: BeignetNodeEvents['channel:ready'] = (data) => {
			expect(data.channelId).to.be.a('string');
		};
		handler({ channelId: 'abc123' });
	});

	it('peer events should receive pubkey', () => {
		const handler: BeignetNodeEvents['peer:connect'] = (data) => {
			expect(data.pubkey).to.be.a('string');
		};
		handler({ pubkey: '02abc' });
	});
});
