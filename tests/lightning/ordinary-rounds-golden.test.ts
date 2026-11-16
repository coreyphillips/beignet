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
import crypto from 'crypto';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import type { IChannelManagerConfig } from '../../src/lightning/channel/channel-manager';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { signRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { isTaprootChannel } from '../../src/lightning/channel/types';
import { randomBytes } from '../../src/lightning/crypto/provider';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import type {
	IOrdinaryRoundsEngine,
	OrdinaryKind
} from './helpers/ordinary-rounds';
import { ordinaryRounds } from './helpers/ordinary-rounds';
import { ordinaryClose } from './helpers/ordinary-close';
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

/** Fails the test that touched it: an ordinary channel asks a provider nothing. */
const untouchable = (what: string): never => {
	throw new Error(`${what} was consulted for an ordinary channel`);
};
/**
 * An asset provider and host of which every member throws when read or
 * called. A node configured with it has to run an ordinary channel without
 * ever reaching for it.
 */
const THROWING: IAuxiliaryChannelConfig = {
	provider: new Proxy({} as IChannelAuxiliaryProvider, {
		get: (_target, name) => untouchable(`provider.${String(name)}`)
	}),
	resolveIncoming: () => untouchable('resolveIncoming'),
	openingCsvPolicy: () => untouchable('openingCsvPolicy'),
	allowLegacyHtlcSignatures: () => untouchable('allowLegacyHtlcSignatures'),
	valueIncomingHtlc: () => untouchable('valueIncomingHtlc'),
	resolveForwardChannel: () => untouchable('resolveForwardChannel'),
	prepareForwardHtlc: () => untouchable('prepareForwardHtlc'),
	onForwardAdmissionFailed: () => untouchable('onForwardAdmissionFailed'),
	onHtlcResolved: () => untouchable('onHtlcResolved'),
	beforeAccept: () => untouchable('beforeAccept'),
	beforeFundingCreated: () => untouchable('beforeFundingCreated'),
	onAccepted: () => untouchable('onAccepted')
};

/** Who runs the life: two nodes configured as before, then two provider nodes. */
const NODES: Array<[string, Partial<IChannelManagerConfig>]> = [
	['two nodes without a provider', {}],
	[
		'two provider nodes whose provider throws if touched',
		{ auxiliaryChannels: THROWING }
	]
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

/**
 * The cooperative close of an ordinary channel, captured the same way from
 * the source of the previous release (4fdaeb60) by running
 * tests/lightning/helpers/ordinary-close.ts against it: an HTLC each way, a
 * shutdown while one is still in flight, the drain, the fee negotiation and
 * the closing transaction each side hands on to be published.
 */
const GOLDEN_CLOSE: Record<
	string,
	{
		types: string;
		wire: string;
		rows: string;
		finalRows: string;
		published: string;
	}
> = {
	'static_remotekey:alice': {
		types:
			'a32 b33 a34 b35 a36 b36 a128 a132 b133 b132 a133 b128 b132 a133 a132 b133 b130 b132 a133 a132 b133 a38 b38 a130 a132 b133 b132 a133 a39 b39',
		wire: '6525842fa66f48d13b51c3b0df33011867e148340d7d7d11e96339e9ccb79eb3',
		rows: '0ce96f02d58dc068f5e640803a6cfcdd8f515a53533586a902924ee0ec92a5b6',
		finalRows:
			'7d9622bc8d409e18a0c48c76da0184493d1ff5598f05eedeee8c877b78603d41',
		published:
			'6ae1aafbd056756e651c1a832a88dd72fa5ed81137ba1584c725d43a2e7ecff2'
	},
	'static_remotekey:bob': {
		types:
			'a32 b33 a34 b35 a36 b36 a128 a132 b133 b132 a133 b128 b132 a133 a132 b133 b130 b132 a133 a132 b133 b38 a38 a130 a132 b133 b132 a133 a39 b39',
		wire: '5fab4926b042b80d888c27c4ab4c56a34d18ef7564df164fe7b94df8f20e48e1',
		rows: '66f03695c127d871b81075a2bb29d23ae827837a4d36dd90bed24b4f329ace16',
		finalRows:
			'70f310b7f47cc157912727d16769a8af1949e6e5687a3156683ac46a71cea418',
		published:
			'a3e3e74c423840162025d4b3be914a66d6223d46fd8b5ed504493c48edc5ac38'
	},
	'anchors:alice': {
		types:
			'a32 b33 a34 b35 a36 b36 a128 a132 b133 b132 a133 b128 b132 a133 a132 b133 b130 b132 a133 a132 b133 a38 b38 a130 a132 b133 b132 a133 a39 b39',
		wire: '0e02974bd6a3c901b76f76e60b6771bc5ce38a5de01ec92d870036e6dc43559b',
		rows: '0b2fca451c02634273829ef6e1f8a832c3b057b69543a803e1c09d162c8f1a47',
		finalRows:
			'99269c00788fffe950e3656c479d49d8629594af345a222ac3762986ed75ddb0',
		published:
			'c48e73308f3046f7c07902883cdcb6fe85faf8a6784827463e19f8c722155f7f'
	},
	'anchors:bob': {
		types:
			'a32 b33 a34 b35 a36 b36 a128 a132 b133 b132 a133 b128 b132 a133 a132 b133 b130 b132 a133 a132 b133 b38 a38 a130 a132 b133 b132 a133 a39 b39',
		wire: '0e9c059f5d4ae55077f86cb48b06e8ee67fb1b5d448ef566cca5fcd338ac682e',
		rows: 'd826cbfdbb045b66cc441038ec71706d52e13bb5cfd063cd59ddf26deac83de4',
		finalRows:
			'cb91673ca4072825181c0995a601ff5cd363c37f1ff604688d3e22fb1905a806',
		published:
			'6d1e42ee09daf49124e29274375f31e65aa89645422e9b5e9324d82461d469d3'
	},
	'taproot:alice': {
		types:
			'a32 b33 a34 b35 a36 b36 a128 a132 b133 b132 a133 b128 b132 a133 a132 b133 b130 b132 a133 a132 b133 a38 b38 a130 a132 b133 b132 a133 a39 b39',
		wire: '63a07f5029b54f90ac73ea7697dc833c4fae8c4057901fd6cc7e373178e7e64c',
		rows: 'e26fc25a43ad25c16cb7934330dd4c49a7418ae925bf25ad8b8b2b086455a329',
		finalRows:
			'a114357d6e583d36b25537e21c9a25bac7211c8daf81ac2d9e04ef3f62a885b5',
		published:
			'8587d8536c01bb06fb707935798cf0bd2268d4de8ace4ef896016467dbe3b057'
	},
	'taproot:bob': {
		types:
			'a32 b33 a34 b35 a36 b36 a128 a132 b133 b132 a133 b128 b132 a133 a132 b133 b130 b132 a133 a132 b133 b38 a38 a130 a132 b133 b132 a133 a39 b39',
		wire: 'f5b753ea18238e42c683efc2980f1abf450e6f8011af77361a09f36a73ce3a2e',
		rows: '3db980344544d8bf0112da6565537be8d28d4f96ad5e858251a7c6a702cd059b',
		finalRows:
			'a8830429453cf409aacaae9a0ba40a45773c1da929019f93c110f7d458427a04',
		published:
			'36814a061a495dd20887f50c0fbe58d69b5b096ed20c5ca2da5f85db45be29ad'
	}
};

describe('an ordinary channel closes cooperatively as it did before (issue #2093)', function () {
	this.timeout(60_000);

	for (const [who, extra] of NODES) {
		for (const kind of ['static_remotekey', 'anchors', 'taproot'] as const) {
			for (const closer of ['alice', 'bob'] as const) {
				it(`a ${kind} channel between ${who}, closed by ${closer}`, () => {
					const closed = ordinaryClose(
						ENGINE,
						kind as OrdinaryKind,
						closer,
						extra
					);
					expect(closed.errors).to.deep.equal([]);
					expect(closed.rowsStored).to.equal(32);
					// Both sides hand on the same transaction.
					expect(closed.published).to.have.length(2);
					expect(closed.published[0].slice(2)).to.equal(
						closed.published[1].slice(2)
					);
					expect({
						types: closed.types,
						wire: closed.wire,
						rows: closed.rows,
						finalRows: closed.finalRows,
						published: crypto
							.createHash('sha256')
							.update(closed.published.join('\n'))
							.digest('hex')
					}).to.deep.equal(GOLDEN_CLOSE[`${kind}:${closer}`]);
				});
			}
		}
	}
});
