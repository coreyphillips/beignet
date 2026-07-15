/**
 * Regression (S-2.H1): update_fail_malformed_htlc must follow the same
 * two-phase removal as update_fail_htlc.
 *
 * The handler used to set the HTLC to FAILED and credit localBalanceMsat
 * IMMEDIATELY while leaving the removal phase flags undefined. The revoke
 * settlement loop then credited the same offered/FAILED HTLC a SECOND time (it
 * only skips entries whose removalRemoteCommitted === false), so any peer
 * relaying a corrupt onion (routine) double-credited our balance and desynced
 * the commitment. The fix defers the refund and sets the phase flags exactly
 * like handleUpdateFailHtlc.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

function makeConfig(name: string): IChannelManagerConfig {
	const seed = sha256(Buffer.from(`malformed-${name}`));
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

const FUNDING_SATOSHIS = 1_000_000n;
const BADONION = 0x8000;

/** A -> B funded channel with a synchronous loopback, plus one committed HTLC. */
function setup(tag: string) {
	const aConfig = makeConfig(`${tag}-A`);
	const bConfig = makeConfig(`${tag}-B`);
	const aPub = getPublicKey(aConfig.nodePrivateKey!).toString('hex');
	const bPub = getPublicKey(bConfig.nodePrivateKey!).toString('hex');
	const a = new ChannelManager(aConfig);
	const b = new ChannelManager(bConfig);
	a.on('error', () => {});
	b.on('error', () => {});
	a.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === bPub) b.handleMessage(aPub, type, payload);
	});
	b.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
		if (peer === aPub) a.handleMessage(bPub, type, payload);
	});

	const aChannel = a.openChannel(bPub, FUNDING_SATOSHIS);
	a.createFunding(aChannel, crypto.randomBytes(32), 0, crypto.randomBytes(64));
	const channelId = aChannel.getChannelId()!;
	a.handleFundingConfirmed(channelId);
	b.handleFundingConfirmed(channelId);
	expect(aChannel.getState()).to.equal(ChannelState.NORMAL);

	// A offers an HTLC to B; the loopback drives the commitment round to
	// completion, so it is fully committed on both sides.
	const hash = sha256(crypto.randomBytes(32));
	a.addHtlc(channelId, 200_000n, hash, 900, Buffer.alloc(1366));
	const offered = [...aChannel.getFullState().htlcs.values()].find(
		(h) => h.direction === HtlcDirection.OFFERED
	)!;
	expect(offered, 'A has a committed offered HTLC').to.exist;

	return { aChannel, channelId, offeredId: offered.id };
}

describe('S-2.H1: update_fail_malformed_htlc two-phase removal', () => {
	it('defers the refund and sets the removal phase flags (no immediate credit)', () => {
		const { aChannel, channelId, offeredId } = setup('defer');
		const before = aChannel.getBalances().localMsat;

		const actions = aChannel.handleUpdateFailMalformedHtlc({
			channelId,
			id: offeredId,
			sha256OfOnion: crypto.randomBytes(32),
			failureCode: BADONION | 4
		});

		// No error, HTLC reported failed.
		expect(actions.find((x) => x.type === 'ERROR')).to.be.undefined;

		// The refund is NOT applied immediately (that was the double-credit source).
		expect(
			aChannel.getBalances().localMsat,
			'balance is unchanged until revoke_and_ack'
		).to.equal(before);

		// The removal is staged through the two-phase flags, like a plain fail.
		const entry = [...aChannel.getFullState().htlcs.values()].find(
			(h) => h.id === offeredId && h.direction === HtlcDirection.OFFERED
		)!;
		expect(entry.state).to.equal(HtlcState.FAILED);
		expect(entry.removalRemoteCommitted).to.equal(false);
		expect(entry.removalLocallyRevoked).to.equal(false);
	});

	it('is idempotent on a reestablish replay (second malformed fail is a no-op)', () => {
		const { aChannel, channelId, offeredId } = setup('dedup');
		const msg = {
			channelId,
			id: offeredId,
			sha256OfOnion: crypto.randomBytes(32),
			failureCode: BADONION | 4
		};
		aChannel.handleUpdateFailMalformedHtlc(msg);
		const afterFirst = aChannel.getBalances().localMsat;

		const replay = aChannel.handleUpdateFailMalformedHtlc(msg);
		expect(replay, 'replay is a no-op').to.deep.equal([]);
		expect(aChannel.getBalances().localMsat).to.equal(afterFirst);
	});
});
