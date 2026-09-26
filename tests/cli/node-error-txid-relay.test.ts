/**
 * Issue #1062: the txid and retention a broadcast error carries have to
 * survive the BeignetNode relay, or SSE, webhooks and the onError callback
 * never see them and a consumer is back to guessing which transaction the
 * watcher gave up on and whether anything is still re-sending it.
 */

import { expect } from 'chai';
import { EventEmitter } from 'events';
import { BeignetNode } from '../../src/cli/beignet-node';
import { formatSseFrame } from '../../src/cli/daemon';
import { ILightningError } from '../../src/lightning/node/types';

type Relayed = {
	code: string;
	message: string;
	timestamp: number;
	channelId?: string;
	txid?: string;
	retained?: boolean;
};

/**
 * A BeignetNode whose engine is a bare emitter, with only the error relay
 * wired: the same prototype idiom beignet-node.test.ts uses, plus a live
 * EventEmitter state so the re-emit has somewhere to go.
 */
function relayFixture(): {
	engine: EventEmitter;
	relayed: Relayed[];
	callback: Relayed[];
} {
	const engine = new EventEmitter();
	const bn = Object.assign(Object.create(BeignetNode.prototype), {
		node: engine
	}) as BeignetNode;
	EventEmitter.call(bn);
	const relayed: Relayed[] = [];
	const callback: Relayed[] = [];
	bn.on('node:error', (e: Relayed) => relayed.push(e));
	(
		bn as unknown as {
			wireNodeErrorRelay: (onError: (e: Relayed) => void) => void;
		}
	).wireNodeErrorRelay((e) => callback.push(e));
	return { engine, relayed, callback };
}

const TXID = 'ab'.repeat(32);

describe('node:error relay carries txid and retained (issue #1062)', () => {
	it('relays txid, retained and the channel id as hex to the re-emit and the callback', () => {
		const { engine, relayed, callback } = relayFixture();
		const message = `Broadcast permanently failed after 12 retries: ${TXID}; the node still holds this transaction and rebroadcasts it on every block until it confirms`;
		engine.emit('node:error', {
			code: 'BROADCAST_PERMANENT_FAILURE',
			message,
			timestamp: 1,
			channelId: Buffer.alloc(32, 7),
			txid: TXID,
			retained: true
		} as ILightningError);
		expect(relayed).to.have.length(1);
		expect(relayed[0]).to.deep.equal({
			code: 'BROADCAST_PERMANENT_FAILURE',
			message,
			timestamp: 1,
			channelId: '07'.repeat(32),
			txid: TXID,
			retained: true
		});
		expect(callback).to.deep.equal(relayed);
	});

	it('keeps a false retained: a dropped close or sweep must not read as still in hand', () => {
		const { engine, relayed } = relayFixture();
		engine.emit('node:error', {
			code: 'BROADCAST_PERMANENT_FAILURE',
			message: 'retries exhausted',
			timestamp: 2,
			txid: TXID,
			retained: false
		} as ILightningError);
		expect(relayed[0].retained).to.equal(false);
		expect(relayed[0].txid).to.equal(TXID);
		expect(relayed[0].channelId).to.equal(undefined);
	});

	it('adds neither key to an error that has no transaction, so older codes are unchanged on the wire', () => {
		const { engine, relayed, callback } = relayFixture();
		engine.emit('node:error', {
			code: 'ELECTRUM_FAILOVER_FAILED',
			message: 'All Electrum servers failed during failover',
			timestamp: 3
		} as ILightningError);
		expect(relayed[0]).to.not.have.property('txid');
		expect(relayed[0]).to.not.have.property('retained');
		expect(callback[0]).to.not.have.property('txid');
		expect(callback[0]).to.not.have.property('retained');
	});

	it('the SSE frame built from the relayed error carries both fields', () => {
		const { engine, relayed } = relayFixture();
		engine.emit('node:error', {
			code: 'SPLICE_BROADCAST_REFUSED',
			message: `splice ${TXID} refused by the chain backend: min relay fee not met`,
			timestamp: 4,
			channelId: Buffer.alloc(32, 9),
			txid: TXID,
			retained: true
		} as ILightningError);
		const frame = formatSseFrame('node:error', relayed[0]);
		expect(frame.startsWith('event: node:error\n')).to.equal(true);
		const data = JSON.parse(frame.slice(frame.indexOf('data: ') + 6));
		expect(data.txid).to.equal(TXID);
		expect(data.retained).to.equal(true);
		expect(data.channelId).to.equal('09'.repeat(32));
		expect(data.code).to.equal('SPLICE_BROADCAST_REFUSED');
	});
});
