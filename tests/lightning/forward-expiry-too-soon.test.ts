/**
 * Issue #1009: a forwarder never applied expiry_too_soon.
 *
 * handleForwardHtlc checked the onion's outgoing_cltv_value only against the
 * INCOMING expiry (our cltv_expiry_delta), never against our chain tip. An
 * upstream could therefore offer B an HTLC that cleared B's delta while its
 * onion told B to forward with an outgoing_cltv_value a thousand blocks in
 * the past, and B relayed it as it was. A downstream beignet then answered
 * the expired add by failing the channel, force-closing B's OUTGOING channel
 * over a payment B had no part in.
 *
 * Alice -> Bob -> Carol over loopback transports, with Alice's onion built by
 * hand (her own payer would never produce one): Bob fails the inbound HTLC
 * with expiry_too_soon, Carol never sees an update_add_htlc, and no channel
 * leaves NORMAL. The control forwards the same shape with a sane expiry.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { ChannelState } from '../../src/lightning/channel/types';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { EXPIRY_TOO_SOON } from '../../src/lightning/onion/types';
import {
	constructOnionPacket,
	encodeOnionPacket
} from '../../src/lightning/onion/construct';
import { computeSharedSecrets } from '../../src/lightning/onion/sphinx-crypto';
import { decryptFailureMessage } from '../../src/lightning/onion/failures';
import {
	createNode,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';

const HEIGHT = 800_000;

interface IChain {
	alice: LightningNode;
	bob: LightningNode;
	carol: LightningNode;
	abChannelId: Buffer;
	bcChannelId: Buffer;
	scidBC: Buffer;
}

function buildChain(): IChain {
	const alice = createNode('e2e-1009', 1);
	const bob = createNode('e2e-1009', 2);
	const carol = createNode('e2e-1009', 3);
	connectNodes(alice, bob);
	connectNodes(bob, carol);
	const abChannelId = openReadyChannel(alice, bob);
	const bcChannelId = openReadyChannel(bob, carol);
	const scidBC = encodeShortChannelId({
		block: 900,
		txIndex: 2,
		outputIndex: 0
	});
	bob.registerChannelScid(bcChannelId, scidBC);
	carol.registerChannelScid(bcChannelId, scidBC);
	for (const n of [alice, bob, carol]) n.handleNewBlock(HEIGHT);
	return { alice, bob, carol, abChannelId, bcChannelId, scidBC };
}

/**
 * Alice offers Bob an HTLC expiring at `incomingCltv` whose onion tells Bob
 * to forward to Carol with `outgoingCltv`. Returns what Bob failed upstream
 * (decrypted with the onion's own secrets) and the adds Bob sent Carol.
 */
function relayThroughBob(
	chain: IChain,
	incomingCltv: number,
	outgoingCltv: number
): { failureCodes: number[]; addsToCarol: number } {
	const { alice, bob, carol, abChannelId, scidBC } = chain;
	const paymentHash = crypto.randomBytes(32);
	const sessionKey = crypto.randomBytes(32);
	const bobPub = Buffer.from(bob.getNodeId(), 'hex');
	const carolPub = Buffer.from(carol.getNodeId(), 'hex');
	const hops = [
		{
			pubkey: bobPub,
			payload: {
				amountToForwardMsat: 1_000_000n,
				outgoingCltvValue: outgoingCltv,
				shortChannelId: scidBC
			}
		},
		{
			pubkey: carolPub,
			payload: {
				amountToForwardMsat: 1_000_000n,
				outgoingCltvValue: outgoingCltv
			}
		}
	];
	const packet = constructOnionPacket(sessionKey, hops, paymentHash);
	const { sharedSecrets } = computeSharedSecrets(sessionKey, [
		bobPub,
		carolPub
	]);

	const reasons: Buffer[] = [];
	const cm = bob.getChannelManager();
	const failHtlc = cm.failHtlc.bind(cm);
	(cm as unknown as { failHtlc: unknown }).failHtlc = (
		c: Buffer,
		id: bigint,
		reason: Buffer
	): unknown => {
		reasons.push(reason);
		return failHtlc(c, id, reason);
	};
	let addsToCarol = 0;
	bob.on('message:outbound', (pk: string, type: number) => {
		if (pk === carol.getNodeId() && type === MessageType.UPDATE_ADD_HTLC) {
			addsToCarol++;
		}
	});

	// Generous fee, so only the expiry decides the outcome.
	const result = alice
		.getChannelManager()
		.addHtlc(
			abChannelId,
			1_100_000n,
			paymentHash,
			incomingCltv,
			encodeOnionPacket(packet)
		);
	expect(result.ok, 'Alice offered the HTLC').to.equal(true);

	const failureCodes = reasons.map((reason) => {
		const decrypted = decryptFailureMessage(sharedSecrets, reason);
		expect(decrypted, 'failure decrypts').to.not.be.null;
		return decrypted!.failure.failureCode;
	});
	return { failureCodes, addsToCarol };
}

function expectAllNormal(chain: IChain): void {
	const { alice, bob, carol, abChannelId, bcChannelId } = chain;
	const views: Array<[string, LightningNode, Buffer]> = [
		['alice ab', alice, abChannelId],
		['bob ab', bob, abChannelId],
		['bob bc', bob, bcChannelId],
		['carol bc', carol, bcChannelId]
	];
	for (const [name, node, channelId] of views) {
		expect(
			node.getChannelManager().getChannel(channelId)!.getState(),
			`${name} stays NORMAL`
		).to.equal(ChannelState.NORMAL);
	}
}

describe('Forward with an outgoing cltv_expiry already past the tip (issue #1009)', function () {
	this.timeout(20_000);

	it('B fails the inbound HTLC with expiry_too_soon; C never sees an add; no channel leaves NORMAL', function () {
		const chain = buildChain();
		// Clears Bob's 40-block delta with one block to spare; the onion's
		// outgoing_cltv_value is a thousand blocks stale.
		const { failureCodes, addsToCarol } = relayThroughBob(
			chain,
			HEIGHT + 41,
			HEIGHT - 1000
		);

		expect(failureCodes).to.deep.equal([EXPIRY_TOO_SOON]);
		expect(addsToCarol, 'Carol never received an add').to.equal(0);
		expect(
			chain.carol
				.getChannelManager()
				.getChannel(chain.bcChannelId)!
				.getFullState().htlcs.size,
			'nothing entered the B-C channel'
		).to.equal(0);
		expectAllNormal(chain);
	});

	it('control: the same shape with a live outgoing expiry is forwarded to C', function () {
		const chain = buildChain();
		const { addsToCarol } = relayThroughBob(chain, HEIGHT + 100, HEIGHT + 60);

		expect(addsToCarol, 'Carol received the add').to.equal(1);
		expectAllNormal(chain);
	});
});
