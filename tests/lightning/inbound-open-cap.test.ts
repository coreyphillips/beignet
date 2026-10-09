/**
 * Issue #1394: a connected peer may hold at most four inbound opens unfunded
 * at once. Before the cap, every open_channel / open_channel2 with a fresh
 * temporary id derived a key set and retained a Channel until the peer
 * disconnected, so a peer that stayed connected could accumulate them
 * without bound. The fifth is refused on the wire before any key is derived.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IPerChannelKeys
} from '../../src/lightning/channel/channel-manager';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { deriveV2TemporaryChannelId } from '../../src/lightning/channel/validation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	encodeOpenChannel2Message,
	IOpenChannel2Message
} from '../../src/lightning/message/dual-funding';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { MessageType } from '../../src/lightning/message/types';

const PEER_A = '02' + 'a1'.repeat(32);
const PEER_B = '02' + 'b2'.repeat(32);
const VICTIM = '03' + 'cd'.repeat(32);
const noop = (): void => {};

function makeSeed(tag: string): Buffer {
	return crypto.createHash('sha256').update(`ioc-${tag}`).digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(derivePrivkey(seed, i));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

/** A deriver that advances the index, so a derivation shows on the counter. */
function makePerChannelKeys(channelIndex: number): IPerChannelKeys {
	const seed = makeSeed(`per-channel-${channelIndex}`);
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		fundingPrivkey,
		basepoints: {
			...makeBasepoints(seed),
			fundingPubkey: getPublicKey(fundingPrivkey)
		},
		perCommitmentSeed: makeSeed(`pcs-${channelIndex}`),
		htlcBasepointSecret: derivePrivkey(seed, 4)
	};
}

function makeManager(tag: string): ChannelManager {
	const seed = makeSeed(tag);
	const manager = new ChannelManager({
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(`${tag}-pcs`),
		localFundingPrivkey: derivePrivkey(seed, 0),
		htlcBasepointSecret: derivePrivkey(seed, 4),
		chainHash: REGTEST_CHAIN_HASH,
		channelKeyDeriver: makePerChannelKeys
	});
	manager.on('error', noop);
	return manager;
}

/** An open_channel payload with a fresh temporary id, captured off the wire. */
function offerOpen(opener: ChannelManager): { payload: Buffer; id: Buffer } {
	let captured: Buffer | null = null;
	const capture = (_peer: string, type: number, payload: Buffer): void => {
		if (type === MessageType.OPEN_CHANNEL) captured = payload;
	};
	opener.on('message:outbound', capture);
	const channel = opener.openChannel(VICTIM, 100_000n);
	opener.off('message:outbound', capture);
	expect(captured, 'captured the open_channel').to.not.equal(null);
	return { payload: captured!, id: channel.getTemporaryChannelId() };
}

function offerOpen2(tag: string): { payload: Buffer; id: Buffer } {
	const remoteBp = makeBasepoints(makeSeed(`${tag}-remote`));
	const remoteSeed = makeSeed(`${tag}-remote-pcs`);
	remoteBp.firstPerCommitmentPoint = perCommitmentPointFromSecret(
		generateFromSeed(remoteSeed, MAX_INDEX)
	);
	const msg: IOpenChannel2Message = {
		chainHash: REGTEST_CHAIN_HASH,
		channelId: deriveV2TemporaryChannelId(remoteBp.revocationBasepoint),
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 500,
		fundingSatoshis: 100_000n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 100_000_000n,
		htlcMinimumMsat: 1n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 30,
		locktime: 0,
		fundingPubkey: remoteBp.fundingPubkey,
		revocationBasepoint: remoteBp.revocationBasepoint,
		paymentBasepoint: remoteBp.paymentBasepoint,
		delayedPaymentBasepoint: remoteBp.delayedPaymentBasepoint,
		htlcBasepoint: remoteBp.htlcBasepoint,
		firstPerCommitmentPoint: remoteBp.firstPerCommitmentPoint,
		secondPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(remoteSeed, MAX_INDEX - 1n)
		),
		channelFlags: 0x01,
		channelType: Buffer.from('1000', 'hex')
	};
	return { payload: encodeOpenChannel2Message(msg), id: msg.channelId };
}

interface IAnswer {
	wireTypes: number[];
	wireErrors: Array<{ channelId: Buffer; data: string }>;
}

/** Feed one inbound message and collect what went back on the wire. */
function inbound(
	target: ChannelManager,
	from: string,
	type: number,
	payload: Buffer
): IAnswer {
	const wire: Array<{ type: number; payload: Buffer }> = [];
	const onWire = (_peer: string, t: number, body: Buffer): void => {
		wire.push({ type: t, payload: body });
	};
	target.on('message:outbound', onWire);
	target.handleMessage(from, type, payload);
	target.off('message:outbound', onWire);
	return {
		wireTypes: wire.map((w) => w.type),
		wireErrors: wire
			.filter((w) => w.type === MessageType.ERROR)
			.map((w) => {
				const decoded = decodeErrorMessage(w.payload);
				return {
					channelId: decoded.channelId,
					data: decoded.data.toString('utf8')
				};
			})
	};
}

function acceptV1(
	target: ChannelManager,
	from: string,
	opener: ChannelManager
): void {
	const open = offerOpen(opener);
	const answer = inbound(target, from, MessageType.OPEN_CHANNEL, open.payload);
	expect(answer.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL]);
	expect(target.getTempChannel(open.id)).to.not.equal(undefined);
}

function acceptV2(target: ChannelManager, from: string, tag: string): void {
	const open = offerOpen2(tag);
	const answer = inbound(target, from, MessageType.OPEN_CHANNEL2, open.payload);
	expect(answer.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL2]);
	expect(target.getTempChannel(open.id)).to.not.equal(undefined);
}

/** The refusal, scoped to the open's id, with nothing derived or retained. */
function expectRefused(
	target: ChannelManager,
	open: { id: Buffer },
	answer: IAnswer,
	indexBefore: number
): void {
	expect(answer.wireTypes).to.deep.equal([MessageType.ERROR]);
	expect(answer.wireErrors[0].channelId.equals(open.id)).to.equal(true);
	expect(answer.wireErrors[0].data).to.match(
		/4 opens from this peer are already pending/
	);
	expect(target.getTempChannel(open.id)).to.equal(undefined);
	expect(target.nextChannelIndex).to.equal(indexBefore);
}

describe('Pending inbound open cap (issue #1394)', () => {
	it('refuses a fifth unfunded open from one peer before deriving keys, v1 and v2 sharing the quota', () => {
		const victim = makeManager('victim');
		const opener = makeManager('opener');
		acceptV1(victim, PEER_A, opener);
		acceptV1(victim, PEER_A, opener);
		acceptV2(victim, PEER_A, 'a-1');
		acceptV2(victim, PEER_A, 'a-2');
		const index = victim.nextChannelIndex;

		const v1 = offerOpen(opener);
		expectRefused(
			victim,
			v1,
			inbound(victim, PEER_A, MessageType.OPEN_CHANNEL, v1.payload),
			index
		);
		const v2 = offerOpen2('a-3');
		expectRefused(
			victim,
			v2,
			inbound(victim, PEER_A, MessageType.OPEN_CHANNEL2, v2.payload),
			index
		);
		expect(victim.listChannels()).to.have.length(4);
	});

	it('counts only opens the peer proposed, per peer, and a disconnect frees the quota', () => {
		const victim = makeManager('victim-scope');
		const opener = makeManager('opener-scope');
		// Our own pending opens to the peer are not its opens.
		for (let i = 0; i < 4; i++) victim.openChannel(PEER_A, 100_000n);
		for (let i = 0; i < 4; i++) acceptV1(victim, PEER_A, opener);
		const refused = offerOpen(opener);
		expectRefused(
			victim,
			refused,
			inbound(victim, PEER_A, MessageType.OPEN_CHANNEL, refused.payload),
			victim.nextChannelIndex
		);

		// Another peer has a quota of its own.
		acceptV1(victim, PEER_B, opener);
		acceptV2(victim, PEER_B, 'b-1');

		// The disconnect sweep retires the peer's pending opens, and with
		// them the quota they held.
		victim.handlePeerDisconnected(PEER_A);
		acceptV1(victim, PEER_A, opener);
		acceptV2(victim, PEER_A, 'a-after');
	});
});
