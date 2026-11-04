/**
 * Issue #1957: a forward whose outgoing add the channel refuses is reported
 * as htlc:forward-refused, not as a CHANNEL_ERROR node:error that reads like
 * a refused send of the node's own.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { LightningNodeEvents } from '../../src/lightning/node/events';
import type {
	ILightningError,
	IStructuredLog
} from '../../src/lightning/node/types';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelErrorCode } from '../../src/lightning/channel/channel-actions';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	ROUTING_INFO_LENGTH,
	TEMPORARY_CHANNEL_FAILURE
} from '../../src/lightning/onion/types';
import { decryptFailureMessage } from '../../src/lightning/onion/failures';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { writableState } from './helpers/writable-state';

type Refused = Parameters<LightningNodeEvents['htlc:forward-refused']>[0];

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

/** A NORMAL 100k sat channel we funded, installed and SCID-registered. */
function installChannel(node: LightningNode): {
	channelId: Buffer;
	scid: Buffer;
} {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 100_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	const channelId = crypto.randomBytes(32);
	const scid = encodeShortChannelId({
		block: 900_000,
		txIndex: 7,
		outputIndex: 0
	});
	state.channelId = channelId;
	state.shortChannelId = scid;
	state.scidAlias = crypto.randomBytes(8);
	state.announceChannel = true;
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	state.channelType = flags.toBuffer();
	// Let the balance check be the one that refuses.
	state.remoteConfig.maxHtlcValueInFlightMsat = 10n ** 15n;
	const channel = new Channel(state);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(node as any).channelManager.restoreChannel(
		channel,
		crypto.randomBytes(33).toString('hex')
	);
	// A restore waits for the peer's reestablish; pretend it came.
	writableState(channel).state = ChannelState.NORMAL;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(node as any).registerChannelScids(channelId);
	return { channelId, scid };
}

describe('A forward refused at the outgoing add (issue #1957)', function () {
	this.timeout(10_000);

	let node: LightningNode;
	let failed: Buffer[];
	let refused: Refused[];
	let errors: ILightningError[];
	let logs: IStructuredLog[];

	beforeEach(function () {
		node = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			perCommitmentSeed: crypto.randomBytes(32),
			channelBasepoints: makeBasepoints(),
			fundingPrivkey: crypto.randomBytes(32)
		});
		failed = [];
		refused = [];
		errors = [];
		logs = [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).channelManager.failHtlc = (
			_c: Buffer,
			_id: bigint,
			reason: Buffer
		): { ok: boolean } => {
			failed.push(reason);
			return { ok: true };
		};
		node.on('htlc:forward-refused', (data) => refused.push(data));
		node.on('node:error', (err) => errors.push(err));
		node.on('log', (log) => logs.push(log));
	});

	afterEach(function () {
		node.destroy();
	});

	it('emits htlc:forward-refused with the refusal and raises no node:error', function () {
		const { channelId, scid } = installChannel(node);
		const inChannelId = crypto.randomBytes(32);
		const paymentHash = crypto.randomBytes(32);
		const sharedSecret = crypto.randomBytes(32);
		const forwarded: unknown[] = [];
		node.on('htlc:forward', (...args) => forwarded.push(args));

		// 150k sats out of a channel holding 100k.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).handleForwardHtlc(
			inChannelId,
			3n,
			paymentHash,
			{
				hopPayload: {
					amountToForwardMsat: 150_000_000n,
					outgoingCltvValue: 700_000,
					shortChannelId: scid
				},
				nextPacket: {
					version: 0,
					ephemeralKey: crypto.randomBytes(33),
					routingInfo: Buffer.alloc(ROUTING_INFO_LENGTH),
					hmac: crypto.randomBytes(32)
				},
				sharedSecret
			},
			151_000_000n,
			700_500
		);

		expect(refused).to.have.length(1);
		expect(refused[0].inChannelId.equals(inChannelId)).to.equal(true);
		expect(refused[0].outChannelId.equals(channelId)).to.equal(true);
		expect(refused[0].paymentHash.equals(paymentHash)).to.equal(true);
		expect(refused[0].amountMsat).to.equal(150_000_000n);
		expect(refused[0].reason).to.equal('Insufficient balance for HTLC');
		expect(refused[0].channelErrorCode).to.equal(
			ChannelErrorCode.INSUFFICIENT_BALANCE
		);
		expect(errors, 'no node:error').to.deep.equal([]);
		expect(forwarded, 'no htlc:forward').to.deep.equal([]);

		// Still failed back, as before.
		expect(failed).to.have.length(1);
		expect(
			decryptFailureMessage([sharedSecret], failed[0])!.failure.failureCode
		).to.equal(TEMPORARY_CHANNEL_FAILURE);

		const entry = logs.find(
			(e) => e.category === 'htlc' && e.action === 'forward_refused'
		);
		expect(entry, 'action log entry').to.not.equal(undefined);
		expect(entry!.data).to.include({
			inChannelId: inChannelId.toString('hex'),
			inHtlcId: 3,
			outChannelId: channelId.toString('hex'),
			amountMsat: '150000000',
			reason: 'Insufficient balance for HTLC',
			channelErrorCode: ChannelErrorCode.INSUFFICIENT_BALANCE
		});
	});
});
