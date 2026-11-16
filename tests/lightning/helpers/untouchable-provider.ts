/**
 * Two ways to run an ordinary channel (issue #2093): on two nodes configured
 * as before asset channels existed, and on two nodes that have an asset
 * provider and host of which every member throws when read or called. An
 * ordinary channel has to live the same life on both.
 */

import type { IChannelManagerConfig } from '../../../src/lightning/channel/channel-manager';
import type { IChannelAuxiliaryProvider } from '../../../src/lightning/channel/auxiliary';
import type { IAuxiliaryChannelConfig } from '../../../src/lightning/channel/auxiliary-funding';

/** Fails the test that touched it: an ordinary channel asks a provider nothing. */
const untouchable = (what: string): never => {
	throw new Error(`${what} was consulted for an ordinary channel`);
};
/**
 * An asset provider and host of which every member throws when read or
 * called. A node configured with it has to run an ordinary channel without
 * ever reaching for it.
 */
export const THROWING: IAuxiliaryChannelConfig = {
	provider: new Proxy({} as IChannelAuxiliaryProvider, {
		get: (_target, name) => untouchable(`provider.${String(name)}`)
	}),
	resolveIncoming: () => untouchable('resolveIncoming'),
	openingCsvPolicy: () => untouchable('openingCsvPolicy'),
	allowLegacyHtlcSignatures: () => untouchable('allowLegacyHtlcSignatures'),
	valueIncomingHtlc: () => untouchable('valueIncomingHtlc'),
	onHtlcResolved: () => untouchable('onHtlcResolved'),
	beforeAccept: () => untouchable('beforeAccept'),
	beforeFundingCreated: () => untouchable('beforeFundingCreated'),
	onAccepted: () => untouchable('onAccepted')
};

/** Who runs the life: two nodes configured as before, then two provider nodes. */
export const ORDINARY_NODES: Array<[string, Partial<IChannelManagerConfig>]> = [
	['two nodes without a provider', {}],
	[
		'two provider nodes whose provider throws if touched',
		{ auxiliaryChannels: THROWING }
	]
];
