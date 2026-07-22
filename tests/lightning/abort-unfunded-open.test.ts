/**
 * Issue #157: a funding failure after accept_channel must tear the channel
 * down, not strand it.
 *
 * handleAutoFunding builds the funding transaction once the peer accepts.
 * When buildFundingTransaction threw (insufficient funds, broadcast failure,
 * the max-funding mismatch guard), the node emitted AUTO_FUNDING_FAILED and
 * stopped: the negotiated channel sat in SENT_OPEN forever, the local channel
 * list accumulated un-fundable entries (a Max open left one visible in
 * SENT_ACCEPT on the dashboard), and the peer held a half-open channel that
 * would never fund. The failure now aborts the pending open: BOLT 1 error to
 * the peer for the temporary channel id, local temp entry removed,
 * channel:aborted emitted.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { IFundingProvider } from '../../src/lightning/node/types';

function makeBasepoints(): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(crypto.randomBytes(32));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(fundingProvider?: IFundingProvider): LightningNode {
	const node = new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32),
		fundingProvider
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

const failingProvider: IFundingProvider = {
	buildFundingTransaction: async () => {
		throw new Error('Insufficient funds for funding transaction');
	},
	broadcastTransaction: async () => {
		throw new Error('unreachable');
	}
};

describe('Issue #157: funding failure after accept_channel aborts the open', function () {
	this.timeout(10_000);

	let alice: LightningNode;
	let bob: LightningNode;

	afterEach(function () {
		alice.destroy();
		bob.destroy();
	});

	async function openAndFailFunding(): Promise<{
		tempId: Buffer;
		aborted: Array<{ temporaryChannelId: Buffer; reason: string }>;
		errorsToBob: Array<{ channelId: Buffer; data: Buffer }>;
	}> {
		const aborted: Array<{ temporaryChannelId: Buffer; reason: string }> = [];
		const errorsToBob: Array<{ channelId: Buffer; data: Buffer }> = [];

		alice.on('channel:aborted', (temporaryChannelId: Buffer, reason: string) =>
			aborted.push({ temporaryChannelId, reason })
		);
		alice.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (type === MessageType.ERROR) {
					errorsToBob.push(decodeErrorMessage(payload));
				}
				if (pubkey === bob.getNodeId()) {
					bob.handlePeerMessage(alice.getNodeId(), type, payload);
				}
			}
		);
		bob.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === alice.getNodeId()) {
					alice.handlePeerMessage(bob.getNodeId(), type, payload);
				}
			}
		);

		// open_channel -> accept_channel happens synchronously over the wiring;
		// handleAutoFunding then fails asynchronously in the provider.
		const channel = alice.openChannel(bob.getNodeId(), 100_000n);
		const tempId = channel.getTemporaryChannelId();
		await new Promise((resolve) => setImmediate(resolve));
		await new Promise((resolve) => setImmediate(resolve));
		return { tempId, aborted, errorsToBob };
	}

	it('removes the stranded channel, tells the peer, and emits channel:aborted', async function () {
		alice = makeNode(failingProvider);
		bob = makeNode();

		const { tempId, aborted, errorsToBob } = await openAndFailFunding();

		// The channel list no longer carries the un-fundable open.
		const remaining = alice
			.getChannelManager()
			.listChannels()
			.filter((c) => c.getTemporaryChannelId()?.equals(tempId));
		expect(remaining, 'stranded channel removed from the list').to.have.length(
			0
		);

		// The peer was told, addressed by the temporary channel id.
		expect(errorsToBob.length, 'BOLT 1 error sent').to.be.greaterThan(0);
		expect(errorsToBob[0].channelId.equals(tempId)).to.equal(true);
		expect(errorsToBob[0].data.toString('utf8')).to.contain(
			'Insufficient funds'
		);

		// And listeners heard about it.
		expect(aborted, 'channel:aborted emitted').to.have.length(1);
		expect(aborted[0].temporaryChannelId.equals(tempId)).to.equal(true);
		expect(aborted[0].reason).to.contain('Insufficient funds');
	});

	it('a successful funding path emits no channel:aborted', async function () {
		// Control: the teardown must be reachable only from the failure path.
		alice = makeNode({
			buildFundingTransaction: async () => ({
				txHex: '00',
				txid: crypto.randomBytes(32),
				outputIndex: 0
			}),
			broadcastTransaction: async () => 'txid'
		});
		bob = makeNode();

		const { aborted } = await openAndFailFunding();
		expect(aborted).to.have.length(0);
	});
});
