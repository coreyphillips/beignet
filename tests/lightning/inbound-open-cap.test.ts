/**
 * Issue #1394: a connected peer may hold at most four inbound opens unfunded
 * at once. Before the cap, every open_channel / open_channel2 with a fresh
 * temporary id derived a key set and retained a Channel until the peer
 * disconnected, so a peer that stayed connected could accumulate them
 * without bound. The fifth is refused on the wire before any key is derived.
 *
 * Issue #1456: an open promoted by funding_created keeps its slot until its
 * funding confirms, across disconnect and restore, because the txid it names
 * need not exist.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IPerChannelKeys
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
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
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';

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

/** keyOffset keeps two managers that complete an open off each other's keys. */
function makeManager(tag: string, keyOffset = 0): ChannelManager {
	const seed = makeSeed(tag);
	const manager = new ChannelManager({
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(`${tag}-pcs`),
		localFundingPrivkey: derivePrivkey(seed, 0),
		htlcBasepointSecret: derivePrivkey(seed, 4),
		chainHash: REGTEST_CHAIN_HASH,
		channelKeyDeriver: (index: number): IPerChannelKeys =>
			makePerChannelKeys(index + keyOffset)
	});
	manager.on('error', noop);
	return manager;
}

/** Wire the opener to the victim, which knows it as PEER_A. */
function connect(victim: ChannelManager, opener: ChannelManager): void {
	opener.on('message:outbound', (peer: string, type: number, body: Buffer) => {
		if (peer === VICTIM) victim.handleMessage(PEER_A, type, body);
	});
	victim.on('message:outbound', (peer: string, type: number, body: Buffer) => {
		if (peer === PEER_A) opener.handleMessage(VICTIM, type, body);
	});
}

/**
 * A complete v1 open whose correctly signed funding_created names a
 * transaction that does not exist. The victim promotes it all the same.
 */
function fundWithNonexistentTx(
	victim: ChannelManager,
	opener: ChannelManager
): Buffer {
	const channel = opener.openChannel(VICTIM, 100_000n);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		Buffer.alloc(64)
	);
	expect(channelId, 'funding_created was accepted').to.not.equal(null);
	expect(victim.getTempChannel(channel.getTemporaryChannelId())).to.equal(
		undefined
	);
	expect(victim.getChannel(channelId!)?.getState()).to.equal(
		ChannelState.AWAITING_FUNDING_CONFIRMED
	);
	return channelId!;
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

describe('Unconfirmed inbound channels keep their quota (issue #1456)', () => {
	function probeRefused(victim: ChannelManager, probe: ChannelManager): void {
		const open = offerOpen(probe);
		expectRefused(
			victim,
			open,
			inbound(victim, PEER_A, MessageType.OPEN_CHANNEL, open.payload),
			victim.nextChannelIndex
		);
	}

	it('counts opens promoted with a nonexistent funding tx, across disconnect, until the funding confirms', () => {
		const victim = makeManager('victim-promoted');
		const opener = makeManager('opener-promoted', 1000);
		const probe = makeManager('probe-promoted', 2000);
		connect(victim, opener);
		const funded: Buffer[] = [];
		for (let i = 0; i < 4; i++) {
			funded.push(fundWithNonexistentTx(victim, opener));
		}
		probeRefused(victim, probe);

		victim.handlePeerDisconnected(PEER_A);
		expect(victim.getChannelsByPeer(PEER_A)).to.have.length(4);
		probeRefused(victim, probe);

		// Funding our own watcher saw gives that channel's slot back.
		victim.handleFundingConfirmed(funded[0]);
		expect(victim.getChannel(funded[0])!.isFundingKnownOnChain()).to.equal(
			true
		);
		acceptV1(victim, PEER_A, probe);
		probeRefused(victim, probe);
	});

	it('counts unconfirmed inbound channels restored from disk', () => {
		const victim = makeManager('victim-restore');
		const opener = makeManager('opener-restore', 1000);
		connect(victim, opener);
		for (let i = 0; i < 4; i++) fundWithNonexistentTx(victim, opener);

		const restarted = makeManager('victim-restore');
		for (const channel of victim.getChannelsByPeer(PEER_A)) {
			const row = deserializeChannelState(
				serializeChannelState(channel.getFullState())
			);
			restarted.restoreChannel(
				new Channel(row),
				PEER_A,
				channel.channelKeyIndex
			);
		}
		probeRefused(restarted, makeManager('probe-restore', 2000));
	});

	it('leaves trusted zero-conf opens out of the count', () => {
		const victim = makeManager('victim-zero-conf');
		const opener = makeManager('opener-zero-conf', 1000);
		connect(victim, opener);
		victim.addTrustedPeer(PEER_A);
		opener.addTrustedPeer(VICTIM);
		for (let i = 0; i < 5; i++) {
			const channel = opener.openChannel(
				VICTIM,
				100_000n,
				undefined,
				undefined,
				{ trusted: true }
			);
			const channelId = opener.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				Buffer.alloc(64)
			);
			expect(channelId, `open ${i + 1} was accepted`).to.not.equal(null);
			expect(victim.getChannel(channelId!)).to.not.equal(undefined);
		}
	});
});
