/**
 * What a wallet without asset channels answers is what the release before
 * asset channels answered (issue #2093).
 *
 * The three answers a host draws a wallet from, GET /balance, GET /liquidity
 * and GET /channels, are read here from a daemon over one stored ordinary
 * channel, twice: with no extension, and with an extension that supplies an
 * asset channel provider and holds only that ordinary channel. Both are the
 * same bytes, and those bytes are the ones pinned below, which were printed
 * by the same reads on master (BEIGNET_PRINT_GOLDENS=1 prints them). The
 * channel's id and its funding txid differ with each run of the fixture and
 * are written here as <channelId> and <fundingTxid>.
 */

import { expect } from 'chai';
import { BeignetNode, BeignetNodeOptions } from '../../src/cli/beignet-node';
import {
	EXTENSION_API_VERSION,
	IExtensionAttachment
} from '../../src/cli/extension';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { referenceProvider } from '../lightning/helpers/auxiliary-pair';
import {
	connectNodes,
	createNode,
	openReadyChannel
} from '../lightning/helpers/loopback-nodes';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const BOOT: BeignetNodeOptions = {
	network: 'regtest',
	mnemonic: MNEMONIC,
	logLevel: 'silent',
	rapidGossipSync: false,
	autoGossipSync: false,
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const json = (value: unknown): string =>
	JSON.stringify(value, (_key, item) =>
		typeof item === 'bigint' ? `${item}n` : item
	);

/** A node's storage holding one ordinary channel that reached NORMAL. */
const storageWithOrdinaryChannel = (): MemoryStorage => {
	const storage = new MemoryStorage();
	const alice = createNode('goldens', 1, undefined, { storage });
	const bob = createNode('goldens', 2);
	alice.on('node:error', () => undefined);
	bob.on('node:error', () => undefined);
	connectNodes(alice, bob);
	openReadyChannel(alice, bob);
	alice.destroy();
	bob.destroy();
	return storage;
};

/** The three answers of a daemon over that storage, as JSON. */
const answers = async (
	extra: Partial<BeignetNodeOptions>
): Promise<{ balance: string; liquidity: string; channels: string }> => {
	const node = await BeignetNode.create({
		...BOOT,
		storage: storageWithOrdinaryChannel(),
		...extra
	});
	try {
		const rows = node.listChannels();
		expect(rows).to.have.length(1);
		// The fixture funds its channel from a fresh transaction each run, so
		// the channel's id and its funding txid are the two values that are
		// not pinned: every other byte of the row is.
		return {
			balance: json(node.getBalance()),
			liquidity: json(node.getLiquiditySnapshot()),
			channels: json(rows)
				.split(rows[0].channelId)
				.join('<channelId>')
				.split(String(rows[0].fundingTxid))
				.join('<fundingTxid>')
		};
	} finally {
		await node.destroy();
	}
};

/** Printed on master, commit 4fdaeb60, by the reads below. */
const GOLDEN = {
	balance:
		'{"onchain":0,"lightning":1000000,"total":1000000,"unsettledSats":0,"splicingSats":0}',
	liquidity:
		'{"totalLocalBalanceSats":0,"totalRemoteBalanceSats":0,"totalCapacitySats":0,"channelCount":1,"activeChannelCount":0,"outboundLiquidityPct":0,"inboundLiquidityPct":0,"reserveSats":0,"sendableSats":0,"maxSendableSats":0,"recommendations":[{"type":"OPEN_CHANNEL","priority":"CRITICAL","reason":"No active channels. All channels are in non-operational states."}]}',
	channels:
		'[{"channelId":"<channelId>","peerPubkey":"03c66b44595b954e885a448ffc7a3979b86fa201cd6809a4017732b9b29a30b208","state":"AWAITING_REESTABLISH","localBalanceSats":1000000,"maxSendableSats":0,"localReserveWaived":false,"remoteReserveWaived":false,"isOpener":true,"localReserveSats":10000,"remoteReserveSats":10000,"remoteBalanceSats":0,"capacitySats":1000000,"isAnchor":true,"preReestablishState":"NORMAL","fundingTxid":"<fundingTxid>","fundingOutputIndex":0,"feeratePerKw":253,"htlcCount":0,"lockedFundingTxids":["<fundingTxid>"],"htlcUsable":false,"isPrivate":false,"feeBaseMsat":1000,"feeProportionalMillionths":1,"cltvExpiryDelta":40,"htlcMinimumMsat":"1000","htlcMaximumMsat":"1000000000"}]'
};

describe('A wallet without asset channels answers what master answers (#2093)', function () {
	this.timeout(90_000);

	it('answers GET /balance, GET /liquidity and GET /channels in the pinned bytes with no extension', async () => {
		const plain = await answers({});
		if (process.env.BEIGNET_PRINT_GOLDENS === '1') {
			// eslint-disable-next-line no-console
			console.log(`GOLDENS ${JSON.stringify(plain)}`);
		}
		expect(plain).to.deep.equal(GOLDEN);
	});

	it('answers the same bytes when an extension supplies an asset channel provider and the wallet holds only the ordinary channel', async () => {
		let attached = 0;
		const withProvider = await answers({
			extensions: [
				{
					id: 'assets',
					version: '1.0.0',
					api: EXTENSION_API_VERSION,
					attach: (): IExtensionAttachment => {
						attached++;
						return {
							auxiliaryChannels: {
								provider: referenceProvider(),
								resolveIncoming: (): undefined => undefined
							}
						};
					}
				}
			]
		});
		expect(attached).to.equal(1);
		expect(withProvider).to.deep.equal(GOLDEN);
	});
});
