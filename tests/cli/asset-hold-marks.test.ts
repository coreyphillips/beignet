/**
 * The daemon carries the node's mark of a held asset HTLC (issue #2093).
 *
 * `auxiliary: true` is on a `hold:accepted`, `hold:settled` or
 * `hold:cancelled` event and on a `GET /invoices/held` row when the node
 * says a part of the set is an asset HTLC, and on no other: the events and
 * rows of an ordinary hold are the bytes they were. `heldAmountMsat` is
 * what the node has, as a string.
 *
 * The events go through the listeners a real daemon node installs, and are
 * read as the SSE frame a client receives.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { expect } from 'chai';
import { BeignetNode, holdInvoiceEvent } from '../../src/cli/beignet-node';
import { formatSseFrame } from '../../src/cli/daemon';

const HOLD_EVENTS = [
	'hold:accepted',
	'hold:settled',
	'hold:cancelled'
] as const;

const methods = BeignetNode.prototype as unknown as Record<
	string,
	(this: unknown, ...args: unknown[]) => Array<Record<string, unknown>>
>;

const HASH = Buffer.alloc(32, 0xcd);
const EXPIRY = {
	minFinalCltvExpiry: 200,
	earliestExpiry: 1_240,
	cancelMarginBlocks: 18,
	cancelHeight: 1_222
};
/** What an event of an ordinary hold of this set is on the wire, as it was. */
const ORDINARY = (state: string, reason?: string): string =>
	`{"paymentHash":"${'cd'.repeat(32)}","state":"${state}",` +
	'"heldAmountMsat":"5000000","htlcCount":1,"minFinalCltvExpiry":200,' +
	'"earliestExpiry":1240,"cancelMarginBlocks":18,"cancelHeight":1222' +
	(reason ? `,"reason":"${reason}"}` : '}');

describe('the daemon marks of a held asset HTLC (issue #2093 step 8)', function () {
	this.timeout(20_000);
	let node: BeignetNode | undefined;
	let dataDir: string;

	before(async () => {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-asset-hold-'));
		node = await BeignetNode.create({
			network: 'regtest',
			dataDir,
			logLevel: 'info',
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false
		});
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(dataDir, { recursive: true, force: true });
	});

	/** The data of each hold event the daemon relays next, as its SSE frame has it. */
	const relayed = (): Array<[string, string]> => {
		const frames: Array<[string, string]> = [];
		for (const event of HOLD_EVENTS) {
			node!.once(event, (data: unknown) => {
				const frame = formatSseFrame(event, data);
				expect(frame.endsWith('\n\n'), event).to.equal(true);
				frames.push([event, frame.slice(`event: ${event}\ndata: `.length, -2)]);
			});
		}
		return frames;
	};

	const emitAll = (mark: { auxiliary?: true }): void => {
		node!.lightningNode.emit('hold:accepted', {
			paymentHash: HASH,
			state: 'ACCEPTED',
			heldAmountMsat: 5_000_000n,
			htlcCount: 1,
			...EXPIRY,
			...mark
		});
		node!.lightningNode.emit('hold:settled', {
			paymentHash: HASH,
			state: 'SETTLED',
			heldAmountMsat: 5_000_000n,
			htlcCount: 1,
			...EXPIRY,
			...mark
		});
		node!.lightningNode.emit('hold:cancelled', {
			paymentHash: HASH,
			reason: 'api',
			heldAmountMsat: 5_000_000n,
			htlcsFailed: 1,
			...EXPIRY,
			...mark
		});
	};

	it('relays auxiliary: true on each hold event of a set the node marked, with the amount the node has', () => {
		const frames = relayed();
		emitAll({ auxiliary: true });
		expect(frames.map(([event]) => event)).to.deep.equal([...HOLD_EVENTS]);
		for (const [event, sse] of frames) {
			const data = JSON.parse(sse) as Record<string, unknown>;
			expect(data.auxiliary, event).to.equal(true);
			expect(data.heldAmountMsat, event).to.equal('5000000');
			expect(data.paymentHash, event).to.equal('cd'.repeat(32));
		}
		const [, cancelled] = frames[2];
		expect(JSON.parse(cancelled)).to.include({
			state: 'CANCELLED',
			reason: 'api',
			htlcCount: 1
		});
	});

	it('relays the hold events of an ordinary set byte for byte as they were', () => {
		const frames = relayed();
		emitAll({});
		expect(frames).to.deep.equal([
			['hold:accepted', ORDINARY('ACCEPTED')],
			['hold:settled', ORDINARY('SETTLED')],
			['hold:cancelled', ORDINARY('CANCELLED', 'api')]
		]);
	});

	it('puts the mark on the wire shape of a transition only when the node set it', () => {
		const base = {
			paymentHash: HASH,
			state: 'ACCEPTED' as const,
			heldAmountMsat: 5_000_000n,
			htlcCount: 1,
			...EXPIRY
		};
		expect(JSON.stringify(holdInvoiceEvent(base))).to.equal(
			ORDINARY('ACCEPTED')
		);
		expect(holdInvoiceEvent({ ...base, auxiliary: true })).to.deep.equal({
			...JSON.parse(ORDINARY('ACCEPTED')),
			auxiliary: true
		});
	});

	it('marks the GET /invoices/held row of a set the node marked and leaves every other row as it was', () => {
		const row = (
			fill: number,
			extra: Record<string, unknown>
		): Record<string, unknown> => ({
			paymentHash: fill.toString(16).padStart(2, '0').repeat(32),
			bolt11: `lnbcrt${fill}`,
			amountMsat: 5_000_000n,
			description: 'held',
			expiry: 3600,
			createdAt: 1_700_000_000,
			state: 'ACCEPTED',
			heldAmountMsat: 5_000_000n,
			htlcCount: 1,
			...EXPIRY,
			...extra
		});
		const rows = methods.listHoldInvoices.call({
			node: {
				listHoldInvoices: () => [
					row(1, { auxiliary: true }),
					row(2, {}),
					row(3, {
						state: 'OPEN',
						heldAmountMsat: 0n,
						htlcCount: 0,
						amountMsat: undefined,
						description: undefined,
						earliestExpiry: null,
						cancelHeight: null
					})
				]
			}
		});
		expect(rows[0].auxiliary).to.equal(true);
		expect(rows[0].heldAmountMsat).to.equal('5000000');
		expect(rows[0].amountSats).to.equal(5000);
		expect(JSON.stringify(rows[1])).to.equal(
			`{"paymentHash":"${'02'.repeat(32)}","bolt11":"lnbcrt2",` +
				'"state":"ACCEPTED","heldAmountMsat":"5000000","htlcCount":1,' +
				'"expiry":3600,"createdAt":1700000000,"minFinalCltvExpiry":200,' +
				'"earliestExpiry":1240,"cancelMarginBlocks":18,"cancelHeight":1222,' +
				'"amountSats":5000,"description":"held"}'
		);
		expect(JSON.stringify(rows[2])).to.equal(
			`{"paymentHash":"${'03'.repeat(32)}","bolt11":"lnbcrt3",` +
				'"state":"OPEN","heldAmountMsat":"0","htlcCount":0,' +
				'"expiry":3600,"createdAt":1700000000,"minFinalCltvExpiry":200,' +
				'"earliestExpiry":null,"cancelMarginBlocks":18,"cancelHeight":null}'
		);
	});
});
