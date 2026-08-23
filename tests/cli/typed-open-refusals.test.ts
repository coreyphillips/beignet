/**
 * Issue #464: a channel open the engine refuses on the caller's own arguments
 * must reach the caller as BeignetError INVALID_PARAMS (HTTP 400) carrying the
 * engine's message. Untyped throws are logged as unhandled faults and scrubbed
 * to a generic 500 "Internal server error", which hid honest refusals such as
 * a push toward a dual-fund peer. Node faults must keep scrubbing, so a plain
 * Error from the engine has to pass through unconverted.
 */

import { expect } from 'chai';
import { BeignetError } from '../../src/cli/errors';
import { BeignetNode } from '../../src/cli/beignet-node';
import { statusForErrorCode } from '../../src/cli/daemon';
import { InvalidChannelOpenError } from '../../src/lightning/node/types';

const PUSH_REFUSAL =
	'push is not possible on a dual-funded (v2) open: open_channel2 has no ' +
	'push_msat. Open without a push and pay the peer once the channel is ready.';

const PUBKEY = '02' + 'ab'.repeat(32);

/**
 * A BeignetNode whose engine is the given stub. Inheriting the prototype keeps
 * the internal helpers resolvable, the same idiom beignet-node.test.ts uses.
 */
function nodeWithEngine(engine: Record<string, unknown>): BeignetNode {
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: engine
	}) as unknown as BeignetNode;
}

/** Every open entry point, driven with arguments its own guards accept. */
const ENTRY_POINTS: Array<{
	name: string;
	engineMethod: string;
	call: (bn: BeignetNode) => unknown;
}> = [
	{
		name: 'openChannel',
		engineMethod: 'openChannel',
		call: (bn): unknown => bn.openChannel(PUBKEY, 100_000, 50_000)
	},
	{
		name: 'openZeroConfChannel',
		engineMethod: 'openZeroConfChannel',
		call: (bn): unknown => bn.openZeroConfChannel(PUBKEY, 100_000, 50_000)
	},
	{
		name: 'openChannelV2',
		engineMethod: 'openChannelV2',
		call: (bn): unknown => bn.openChannelV2(PUBKEY, { amountSats: 100_000 })
	}
];

describe('Issue #464: channel-open refusals reach the caller typed', () => {
	for (const entry of ENTRY_POINTS) {
		it(`${entry.name} converts an argument refusal to INVALID_PARAMS`, () => {
			const bn = nodeWithEngine({
				[entry.engineMethod]: (): never => {
					throw new InvalidChannelOpenError(PUSH_REFUSAL);
				}
			});
			try {
				entry.call(bn);
				expect.fail('expected the open to be refused');
			} catch (err: unknown) {
				expect(err).to.be.instanceOf(BeignetError);
				const beignetErr = err as BeignetError;
				expect(beignetErr.code).to.equal('INVALID_PARAMS');
				// The engine's message is the whole point: a caller told to
				// open without a push can act on it, "Internal server error"
				// is a dead end.
				expect(beignetErr.message).to.equal(PUSH_REFUSAL);
			}
		});

		it(`${entry.name} leaves a node fault untyped, so it still scrubs`, () => {
			const bn = nodeWithEngine({
				[entry.engineMethod]: (): never => {
					throw new Error('database is locked');
				}
			});
			try {
				entry.call(bn);
				expect.fail('expected the open to throw');
			} catch (err: unknown) {
				expect(err).to.be.instanceOf(Error);
				expect(err).to.not.be.instanceOf(BeignetError);
				expect((err as Error).message).to.equal('database is locked');
			}
		});
	}

	it('answers 400, not the 500 the issue reported', () => {
		expect(statusForErrorCode('INVALID_PARAMS')).to.equal(400);
		expect(statusForErrorCode('INTERNAL_ERROR')).to.equal(500);
	});
});
