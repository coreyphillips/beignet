/**
 * Issue #1690: LightningNode, ChannelManager and BeignetNode take their event
 * names and listener signatures from typed maps, and the README's events
 * table is generated from LightningNodeEvents (checked against the README in
 * doc-tables.test.ts).
 *
 * The @ts-expect-error lines are the point of most of this file: they are
 * checked by `npm run tsc:check:tests`, which fails if any of them compiles.
 */
import { expect } from 'chai';
import { TypedEmitter } from '../../src/utils/typed-emitter';
import type { LightningNode } from '../../src/lightning/node/lightning-node';
import type { NodeErrorCode } from '../../src/lightning/node/events';
import type { ChannelManager } from '../../src/lightning/channel/channel-manager';
import type { BeignetNode } from '../../src/cli/beignet-node';
import { DOC_TABLES, renderTable } from '../../scripts/doc-tables';

interface ITestEvents {
	ping: (n: number) => void;
	pair: (a: string, b: boolean) => void;
	empty: () => void;
}

/** Never called: tsc checks these, mocha does not run them. */
export function compileTimeChecks(
	node: LightningNode,
	manager: ChannelManager,
	beignet: BeignetNode
): void {
	// @ts-expect-error a misspelled event does not compile
	node.on('payment:snet', () => undefined);
	// @ts-expect-error LightningNode never emits the bare 'error' event
	node.on('error', () => undefined);
	// @ts-expect-error LightningNode passes the pubkey itself, not an object
	node.emit('peer:connect', { pubkey: '02' });
	node.emit('node:error', {
		// @ts-expect-error not a NodeErrorCode
		code: 'NOT_A_CODE',
		message: 'm',
		timestamp: 0
	});
	node.on('node:error', (error) => {
		// The code is the closed union, so this switch can be exhaustive.
		const code: NodeErrorCode = error.code;
		void code;
	});
	node.on('channel:ready', ({ channelId }) => channelId.toString('hex'));
	// @ts-expect-error ChannelManager's channel:ready passes the id itself
	manager.on('channel:ready', ({ channelId }) => channelId);
	manager.on('error', (channelId, message) => [channelId?.length, message]);
	// @ts-expect-error BeignetNode no longer has a fallback string overload
	beignet.on('payment:snet', () => undefined);
	// @ts-expect-error BeignetNode relays peer:connect as an object
	beignet.emit('peer:connect', '02');
}

describe('Typed event maps (issue #1690)', function () {
	describe('TypedEmitter', () => {
		it('delivers each argument to on, once and prepend listeners', () => {
			const emitter = new TypedEmitter<ITestEvents>();
			const seen: string[] = [];
			emitter.on('pair', (a, b) => seen.push(`on:${a}:${b}`));
			emitter.prependListener('pair', (a) => seen.push(`first:${a}`));
			emitter.once('pair', (a) => seen.push(`once:${a}`));
			expect(emitter.emit('pair', 'x', true)).to.equal(true);
			emitter.emit('pair', 'y', false);
			expect(seen).to.deep.equal([
				'first:x',
				'on:x:true',
				'once:x',
				'first:y',
				'on:y:false'
			]);
			expect(emitter.emit('empty')).to.equal(false);
		});

		it('removes listeners, one event or all of them', () => {
			const emitter = new TypedEmitter<ITestEvents>();
			const ping = (): void => undefined;
			emitter.on('ping', ping);
			emitter.addListener('ping', ping);
			emitter.on('empty', () => undefined);
			expect(emitter.listenerCount('ping')).to.equal(2);
			expect(emitter.listeners('ping')).to.deep.equal([ping, ping]);
			emitter.off('ping', ping);
			emitter.removeListener('ping', ping);
			expect(emitter.listenerCount('ping')).to.equal(0);
			emitter.on('ping', ping);
			emitter.removeAllListeners('ping');
			expect(emitter.eventNames()).to.deep.equal(['empty']);
			emitter.removeAllListeners();
			expect(emitter.eventNames()).to.deep.equal([]);
		});

		it("lists once() wrappers in rawListeners, each taking the event's arguments", () => {
			const emitter = new TypedEmitter<ITestEvents>();
			const got: number[] = [];
			emitter.once('ping', (n) => got.push(n));
			const [wrapper] = emitter.rawListeners('ping');
			wrapper(7);
			expect(got).to.deep.equal([7]);
			expect(emitter.listenerCount('ping')).to.equal(0);
		});
	});

	it('the generated table lists the events the hand-written one left out', function () {
		this.timeout(60_000);
		const table = DOC_TABLES.find((t) => t.name === 'LightningNodeEvents');
		const rendered = renderTable(table!);
		for (const event of [
			'channel:force-closing',
			'htlc:held-forward',
			'htlc:held-forward-released',
			'htlc:held-forward-failed',
			'recovery:durable',
			'ffor:state',
			'ffor:witness-provisioned',
			'graph:restored',
			'block:processed',
			'jit:intent',
			'direct-funding:offer:accepted',
			'swap:funding-seen'
		]) {
			expect(rendered).to.include(`| \`${event}\` |`);
		}
	});
});
