/**
 * Systemic wire-error regression (2026-07-15 review): "MUST send an error and
 * fail the channel" paths previously only emitted an app-level 'error' event.
 * No wire error ever reached the peer and the channel state stayed NORMAL, so
 * an invalid commitment_signed or a bad revocation secret left the connection
 * open and the channel wedged on provably-desynced state, with the peer never
 * learning it should force-close.
 *
 * The DLP fell-behind pattern (persist -> wire error -> app error, state
 * ERRORED) is now generalized via Channel._failChannelWithWireError and
 * applied to the peer-protocol-violation paths: invalid commitment signature,
 * invalid HTLC signature, invalid revocation secret, and the reestablish
 * per-commitment-secret check. Local API misuse keeps returning plain ERROR
 * actions (a wire error would kill a healthy channel at the peer).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decodeErrorMessage } from '../../src/lightning/message/error';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function makeConfig(name: string): IChannelManagerConfig {
	const seed = sha256(Buffer.from(`wire-error-${name}`));
	const k = (i: number): Buffer =>
		sha256(Buffer.concat([seed, Buffer.from([i])]));
	const basepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(k(0)),
		revocationBasepoint: getPublicKey(k(1)),
		paymentBasepoint: getPublicKey(k(2)),
		delayedPaymentBasepoint: getPublicKey(k(3)),
		htlcBasepoint: getPublicKey(k(4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: basepoints,
		localPerCommitmentSeed: sha256(Buffer.from(`${name}-commit`)),
		localFundingPrivkey: k(0),
		htlcBasepointSecret: k(4),
		nodePrivateKey: sha256(Buffer.from(`${name}-node`)),
		preferAnchors: true
	};
}

interface IPair {
	A: ChannelManager;
	B: ChannelManager;
	channelId: Buffer;
	aChannel: Channel;
	bChannel: Channel;
	errors: string[];
	/** Wire messages captured per direction (type, payload). */
	toB: Array<{ type: number; payload: Buffer }>;
	toA: Array<{ type: number; payload: Buffer }>;
	/** Mutate the next message of `type` sent A->B before delivery. */
	corruptNext: (type: MessageType, mutate: (p: Buffer) => Buffer) => void;
	/** Drop everything from the next message of `type` (fromB) onward. */
	cutBefore: (type: MessageType, fromB?: boolean) => void;
}

function makePair(tag: string): IPair {
	const aConfig = makeConfig(`${tag}-A`);
	const bConfig = makeConfig(`${tag}-B`);
	const aPub = getPublicKey(aConfig.nodePrivateKey!).toString('hex');
	const bPub = getPublicKey(bConfig.nodePrivateKey!).toString('hex');
	const A = new ChannelManager(aConfig);
	const B = new ChannelManager(bConfig);
	const errors: string[] = [];
	const toB: Array<{ type: number; payload: Buffer }> = [];
	const toA: Array<{ type: number; payload: Buffer }> = [];

	let corrupt: {
		type: MessageType;
		mutate: (p: Buffer) => Buffer;
	} | null = null;
	let cutType: MessageType | null = null;
	let cutFromB = false;
	let alive = true;

	A.on('error', (_id, m: string) => errors.push(`A: ${m}`));
	B.on('error', (_id, m: string) => errors.push(`B: ${m}`));
	A.on('message:outbound', (to: string, type: number, p: Buffer) => {
		if (to !== bPub || !alive) return;
		if (cutType !== null && type === cutType && !cutFromB) {
			alive = false;
			return;
		}
		let payload = p;
		if (corrupt && type === corrupt.type) {
			payload = corrupt.mutate(Buffer.from(p));
			corrupt = null;
		}
		toB.push({ type, payload });
		B.handleMessage(aPub, type, payload);
	});
	B.on('message:outbound', (to: string, type: number, p: Buffer) => {
		if (to !== aPub || !alive) return;
		if (cutType !== null && type === cutType && cutFromB) {
			alive = false;
			return;
		}
		toA.push({ type, payload: p });
		A.handleMessage(bPub, type, p);
	});

	const aChan = A.openChannel(bPub, 1_000_000n);
	A.createFunding(aChan, crypto.randomBytes(32), 0, crypto.randomBytes(64));
	const channelId = aChan.getChannelId()!;
	A.handleFundingConfirmed(channelId);
	B.handleFundingConfirmed(channelId);
	const bChan = B.getChannelsByPeer(aPub)[0];
	expect(aChan.getState()).to.equal(ChannelState.NORMAL);

	return {
		A,
		B,
		channelId,
		aChannel: aChan,
		bChannel: bChan,
		errors,
		toB,
		toA,
		corruptNext: (type, mutate): void => {
			corrupt = { type, mutate };
		},
		cutBefore: (type, fromB = false): void => {
			cutType = type;
			cutFromB = fromB;
		}
	};
}

const wireErrorsIn = (
	msgs: Array<{ type: number; payload: Buffer }>
): string[] =>
	msgs
		.filter((m) => m.type === MessageType.ERROR)
		.map((m) => decodeErrorMessage(m.payload).data.toString('ascii'));

describe('wire error + channel failure on peer protocol violations', function () {
	it('a corrupted commitment_signed triggers a WIRE error and fails the channel', function () {
		const t = makePair('bad-commit-sig');
		// Corrupt the 64-byte signature inside A's next commitment_signed
		// (starts right after the 32-byte channel_id).
		t.corruptNext(MessageType.COMMITMENT_SIGNED, (p) => {
			p[32] ^= 0xff;
			p[40] ^= 0xff;
			return p;
		});
		t.A.addHtlc(
			t.channelId,
			1_000_000n,
			sha256(crypto.randomBytes(32)),
			900,
			Buffer.alloc(1366)
		);

		// B told A over the WIRE that the channel is failed.
		const wireErrors = wireErrorsIn(t.toA);
		expect(wireErrors.length, 'wire error sent').to.be.greaterThan(0);
		expect(wireErrors.join('; ')).to.contain('Invalid commitment signature');
		// And B refuses to keep operating on the desynced state.
		expect(t.bChannel.getState()).to.equal(ChannelState.ERRORED);
		// The app-level error still fires for the embedder.
		expect(t.errors.join('; ')).to.contain('Invalid commitment signature');
	});

	it('a bad revocation secret triggers a WIRE error and fails the channel', function () {
		const t = makePair('bad-revoke');
		// Round 1 completes fully so A holds B's genuine secret #0 (the FIRST
		// secret has nothing to derive against, so only later ones are
		// cryptographically checkable — exactly how the shachain works).
		const preimage = crypto.randomBytes(32);
		t.A.addHtlc(
			t.channelId,
			1_000_000n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		t.B.fulfillHtlc(t.channelId, 0n, preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);

		// Round 2: drop B's revoke_and_ack so A keeps an outstanding
		// commitment, then hand A a FORGED revocation for it.
		t.cutBefore(MessageType.REVOKE_AND_ACK, true);
		t.A.addHtlc(
			t.channelId,
			1_000_000n,
			sha256(crypto.randomBytes(32)),
			900,
			Buffer.alloc(1366)
		);
		const actions = t.aChannel.handleRevokeAndAck({
			channelId: t.channelId,
			perCommitmentSecret: crypto.randomBytes(32), // cannot derive secret #0
			nextPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
		});

		const wireError = actions.find(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				(a as { messageType: MessageType }).messageType === MessageType.ERROR
		) as { payload: Buffer } | undefined;
		expect(wireError, 'wire error action returned').to.not.equal(undefined);
		expect(
			decodeErrorMessage(wireError!.payload).data.toString('ascii')
		).to.match(/per-commitment (secret|point)/);
		expect(t.aChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	it('a lying reestablish per-commitment secret triggers a WIRE error', function () {
		const t = makePair('bad-reest-secret');
		// A committed round so revocation numbers are past zero.
		const preimage = crypto.randomBytes(32);
		t.A.addHtlc(
			t.channelId,
			1_000_000n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		t.B.fulfillHtlc(t.channelId, 0n, preimage);
		expect(t.errors, t.errors.join('; ')).to.have.length(0);

		t.aChannel.markForReestablish();
		const st = t.aChannel.getFullState();
		const actions = t.aChannel.handleReestablish({
			channelId: t.channelId,
			nextCommitmentNumber: st.remoteCommitmentNumber + 1n,
			// Claims to have revoked one of ours but presents a bogus secret.
			nextRevocationNumber: st.localCommitmentNumber,
			yourLastPerCommitmentSecret: crypto.randomBytes(32),
			myCurrentPerCommitmentPoint: Buffer.alloc(33)
		});
		const wireError = actions.find(
			(a) =>
				a.type === ChannelActionType.SEND_MESSAGE &&
				(a as { messageType: MessageType }).messageType === MessageType.ERROR
		);
		expect(wireError, 'wire error action returned').to.not.equal(undefined);
		expect(t.aChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	it('control: local API misuse stays an app-level error (no wire error, channel healthy)', function () {
		const t = makePair('local-misuse');
		const before = t.toB.filter((m) => m.type === MessageType.ERROR).length;
		// Fulfilling a nonexistent HTLC is OUR bug, not the peer's: it must not
		// kill the channel at the peer.
		t.B.fulfillHtlc(t.channelId, 99n, crypto.randomBytes(32));
		expect(
			t.toA.filter((m) => m.type === MessageType.ERROR).length,
			'no wire error sent'
		).to.equal(0);
		expect(t.toB.filter((m) => m.type === MessageType.ERROR).length).to.equal(
			before
		);
		expect(t.bChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(t.aChannel.getState()).to.equal(ChannelState.NORMAL);
	});
});
