/**
 * The electrumConnection poll is subscriber scoped.
 *
 * It used to be started by the module-level IIFE at import time and never
 * cleared, which pinned the event loop of every process that imported the
 * library (see tests/cli/cli-help-exit.test.ts for the user-visible half of
 * that). These cases cover the replacement directly: nothing polls until
 * something subscribes, one poll serves every subscriber, the last one to
 * leave stops it, and a later subscriber starts a fresh one.
 *
 * The timers are recorded through the globals rather than read out of the
 * module, which keeps the assertions to public behaviour.
 */

import { expect } from 'chai';

import { ElectrumConnectionSubscription, electrumConnection } from '../src';

describe('electrumConnection poll lifecycle', () => {
	let created: unknown[] = [];
	let cleared: Set<unknown> = new Set();
	let subscriptions: ElectrumConnectionSubscription[] = [];
	const realSetInterval = global.setInterval;
	const realClearInterval = global.clearInterval;

	/** Subscribes and remembers it, so a failed case still tears its poll down. */
	const subscribe = (): ElectrumConnectionSubscription => {
		const subscription = electrumConnection.subscribe(() => undefined);
		subscriptions.push(subscription);
		return subscription;
	};

	beforeEach(() => {
		created = [];
		cleared = new Set();
		subscriptions = [];
		global.setInterval = ((...args: unknown[]): NodeJS.Timeout => {
			const timer = (realSetInterval as (...a: unknown[]) => NodeJS.Timeout)(
				...args
			);
			created.push(timer);
			return timer;
		}) as unknown as typeof global.setInterval;
		global.clearInterval = ((timer: unknown): void => {
			cleared.add(timer);
			(realClearInterval as (t: unknown) => void)(timer);
		}) as unknown as typeof global.clearInterval;
	});

	afterEach(() => {
		global.setInterval = realSetInterval;
		global.clearInterval = realClearInterval;
		// Drop whatever a failed case left subscribed, which stops its poll.
		// Removing by subscription rather than clearing the recorded handles,
		// so a timer some other suite happened to create in the same window is
		// never touched. remove() is idempotent.
		subscriptions.forEach((subscription) => subscription.remove());
	});

	it('starts one poll for the first subscriber and none for the second', () => {
		const first = subscribe();
		expect(created.length, 'the first subscriber started the poll').to.equal(1);

		const second = subscribe();
		expect(created.length, 'the second subscriber shares that poll').to.equal(
			1
		);

		first.remove();
		expect(
			cleared.has(created[0]),
			'the poll runs on while a subscriber remains'
		).to.equal(false);

		second.remove();
		expect(
			cleared.has(created[0]),
			'the last subscriber to leave stopped the poll'
		).to.equal(true);
	});

	it('starts a fresh poll for a subscriber that arrives after the last one left', () => {
		subscribe().remove();
		expect(created.length).to.equal(1);
		expect(cleared.has(created[0])).to.equal(true);

		const later = subscribe();
		expect(created.length, 'the poll was restarted').to.equal(2);
		expect(cleared.has(created[1]), 'the new poll is running').to.equal(false);
		later.remove();
	});

	it('unrefs the poll so a subscribed process can still exit', () => {
		const sub = subscribe();
		expect(
			(created[0] as NodeJS.Timeout).hasRef(),
			'the poll does not hold the event loop open'
		).to.equal(false);
		sub.remove();
	});
});
