/**
 * An ordinary channel lives the life it lived before asset channels existed
 * (issue #2093). The opens are pinned to channel_ready elsewhere; this pins
 * what follows: HTLC adds, fee updates, a fulfil and a fail each way, and a
 * force close by either side, for the three kinds of ordinary channel.
 *
 * The digests were captured from the source of the previous release
 * (4fdaeb60) by running tests/lightning/helpers/ordinary-rounds.ts against
 * it under the same counter in place of randomness. They cover every
 * message on the wire, every row either side stored, the final rows and
 * what the force close returned.
 */

import { expect } from 'chai';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import type { IChannelManagerConfig } from '../../src/lightning/channel/channel-manager';
import { signRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { isTaprootChannel } from '../../src/lightning/channel/types';
import { randomBytes } from '../../src/lightning/crypto/provider';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import type {
	IOrdinaryRoundsEngine,
	OrdinaryKind
} from './helpers/ordinary-rounds';
import { ordinaryRounds } from './helpers/ordinary-rounds';
import { configOf, seedFor } from './helpers/taproot-revoked-fixture';

const ENGINE: IOrdinaryRoundsEngine = {
	ChannelManager,
	configOf,
	seedFor,
	signRemoteCommitment,
	isTaprootChannel,
	serializeChannelState,
	randomBytes
};

/** The message types of the life, the same for every kind. */
const TYPES =
	'a32 b33 a34 b35 a36 b36 a128 a132 b133 b132 a133 a128 a132 b133 b132 a133 b128 b132 a133 a132 b133 a128 a132 b133 b132 a133 b128 b132 a133 a132 b133 a128 a132 b133 b132 a133 a134 a132 b133 b132 a133 a134 a132 b133 b132 a133 b130 b132 a133 a132 b133 a130 a132 b133 b132 a133 b131 b132 a133 a132 b133 a131 a132 b133 b132 a133';

const GOLDEN: Record<
	string,
	{ wire: string; rows: string; finalRows: string; forceClose: string }
> = {
	'static_remotekey:alice': {
		wire: '387cee8a688511ea377f6df4037ceebf924daae9f79b7ad7740c212e52debc04',
		rows: '7d7e9f7b6058f14a097d2c3de51641b48c950f70594d922c467171f763106a1b',
		finalRows:
			'cdca12d29bad068d68d42fb5d8fa721ed568346629dea53e4210e0e371805a0a',
		forceClose:
			'4d19b7c0b7c7f8208dfd9c2e9f3ebdae031e1b3cf7c0093109c92d0afb26a2b6'
	},
	'static_remotekey:bob': {
		wire: '387cee8a688511ea377f6df4037ceebf924daae9f79b7ad7740c212e52debc04',
		rows: '7d7e9f7b6058f14a097d2c3de51641b48c950f70594d922c467171f763106a1b',
		finalRows:
			'cdca12d29bad068d68d42fb5d8fa721ed568346629dea53e4210e0e371805a0a',
		forceClose:
			'876cca0081f0e2167a2f112160b9d3bcb73bddc44c85c17457a9bca73512cb00'
	},
	'anchors:alice': {
		wire: '0ff74eb7027798ab2ebf9005b4ac5db9efb67b50d1f62db9d35ba3722ece4c7a',
		rows: '438b4fc95365ad4ef336e51350f7abb69fef00d727592d99ad91bf98079df7ce',
		finalRows:
			'e64de8f70e9b1c73f2c805ad305b1032edbfe76cc30ab1d4ee6fbf4da5697c23',
		forceClose:
			'77b13567bbb0538ac36b471ad11d3aa0fa90839c7b70a816b19c1ea88de38f40'
	},
	'anchors:bob': {
		wire: '0ff74eb7027798ab2ebf9005b4ac5db9efb67b50d1f62db9d35ba3722ece4c7a',
		rows: '438b4fc95365ad4ef336e51350f7abb69fef00d727592d99ad91bf98079df7ce',
		finalRows:
			'e64de8f70e9b1c73f2c805ad305b1032edbfe76cc30ab1d4ee6fbf4da5697c23',
		forceClose:
			'eac402d59b54a298bd64477d346c36d0fcdc640cb34773bc9a475494bdc772bf'
	},
	'taproot:alice': {
		wire: '0b7c7954f6b61607b5f5d474fb85b0d60dafd65c4e8b21e7648578cbadd5bc89',
		rows: 'b6d03a0afb2adc9371a42fc0120882d972aa8a0ba5e126b4269716069475c96e',
		finalRows:
			'5530c7746b41cdc43f0438327f15d04edcb7fe772a7706af55594b27d88adf04',
		forceClose:
			'234931df4992aec530f4b6d49cf52e5b5b43e248755e477db1bb013ad5dd7cdd'
	},
	'taproot:bob': {
		wire: '0b7c7954f6b61607b5f5d474fb85b0d60dafd65c4e8b21e7648578cbadd5bc89',
		rows: 'b6d03a0afb2adc9371a42fc0120882d972aa8a0ba5e126b4269716069475c96e',
		finalRows:
			'5530c7746b41cdc43f0438327f15d04edcb7fe772a7706af55594b27d88adf04',
		forceClose:
			'2a971509878a359641a102c6b2db4576bb852df4512d252bced8a7f2f67bb9a7'
	}
};

/** Who runs the life, beside two nodes configured as before. */
const NODES: Array<[string, Partial<IChannelManagerConfig>]> = [
	['two nodes without a provider', {}]
];

describe('an ordinary channel lives the life it did before (issue #2093)', function () {
	this.timeout(60_000);

	for (const [who, extra] of NODES) {
		for (const kind of ['static_remotekey', 'anchors', 'taproot'] as const) {
			for (const closer of ['alice', 'bob'] as const) {
				it(`a ${kind} channel between ${who}, force closed by ${closer}`, () => {
					const lived = ordinaryRounds(
						ENGINE,
						kind as OrdinaryKind,
						closer,
						extra
					);
					expect(lived.types).to.equal(TYPES);
					expect(lived.messages).to.equal(66);
					expect(lived.rowsStored).to.equal(86);
					expect(lived.keyIndexes).to.equal('1,1');
					expect({
						wire: lived.wire,
						rows: lived.rows,
						finalRows: lived.finalRows,
						forceClose: lived.forceClose
					}).to.deep.equal(GOLDEN[`${kind}:${closer}`]);
				});
			}
		}
	}
});
