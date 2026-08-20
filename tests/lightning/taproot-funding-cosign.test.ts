import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	isTaprootChannel
} from '../../src/lightning/channel/types';
import {
	buildLocalCommitment,
	aggregateLocalCommitmentSig
} from '../../src/lightning/channel/commitment-builder';
import { taprootCommitmentSighash } from '../../src/lightning/channel/commitment-musig';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Channel } from '../../src/lightning/channel/channel';
import { MessageType } from '../../src/lightning/message/types';
import { decodeErrorMessage } from '../../src/lightning/message/error';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`taproot-funding-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeConfig(
	seedId: number,
	preferTaproot: boolean
): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey,
		htlcBasepointSecret,
		preferTaproot
	};
}

function connectManagers(
	managerA: ChannelManager,
	pubkeyA: string,
	managerB: ChannelManager,
	pubkeyB: string
): void {
	managerA.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === pubkeyB) managerB.handleMessage(pubkeyA, type, payload);
		}
	);
	managerB.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === pubkeyA) managerA.handleMessage(pubkeyB, type, payload);
		}
	);
}

/**
 * Aggregate a channel's stored remote partial (the peer's MuSig2 partial over OUR
 * local commitment #0) with our own partial, and assert the result is a valid
 * BIP340 key-spend signature for the 2-of-2 funding output. This is the proof
 * that the funding co-sign produced a usable, broadcastable signature.
 */
function assertAggregatesToValidKeySpend(channel: Channel): void {
	const state = channel.getFullState();
	const signer = channel.getSigner();
	expect(signer, 'channel signer').to.not.be.null;
	expect(state.localNonce, 'our verification nonce').to.exist;
	expect(state.remoteSigningNonce, 'peer signing nonce').to.exist;
	expect(state.remoteSigningNonce!.length).to.equal(66);
	expect(state.remoteCommitmentSignature, 'peer partial').to.exist;
	expect(state.remoteCommitmentSignature!.length).to.equal(32);

	const firstPoint = state.localBasepoints.firstPerCommitmentPoint;
	const finalSig = aggregateLocalCommitmentSig(
		state,
		signer!,
		state.localNonce!,
		state.remoteSigningNonce!,
		state.remoteCommitmentSignature!,
		firstPoint,
		0n
	);

	const funding = createTaprootFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey
	);
	const built = buildLocalCommitment(state, firstPoint, 0n);
	const sighash = taprootCommitmentSighash(
		built.result.tx,
		funding.p2trOutput,
		Number(state.fundingSatoshis)
	);
	expect(ecc.verifySchnorr(sighash, funding.outputKey, finalSig)).to.equal(
		true
	);
}

describe('option_taproot funding co-sign (Stage A)', function () {
	const aliceConfig = makeConfig(1, true);
	const bobConfig = makeConfig(2, false);
	const alicePubkey = aliceConfig.localBasepoints.fundingPubkey.toString('hex');
	const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');

	it('completes a beignet↔beignet taproot funding handshake with valid aggregable partials', function () {
		const alice = new ChannelManager(aliceConfig);
		const bob = new ChannelManager(bobConfig);
		connectManagers(alice, alicePubkey, bob, bobPubkey);

		// Alice opens with preferTaproot → open_channel/accept_channel exchange the
		// verification nonces via loopback.
		const aliceChannel = alice.openChannel(bobPubkey, 1_000_000n);

		// Alice funds → funding_created (partial over Bob's #0) → funding_signed
		// (partial over Alice's #0) via loopback.
		const fundingTxid = crypto.randomBytes(32);
		const channelId = alice.createFunding(
			aliceChannel,
			fundingTxid,
			0,
			crypto.randomBytes(64)
		);
		expect(channelId, 'funding produced a channel id').to.not.be.null;

		const bobChannel = bob.getChannel(channelId!);
		expect(bobChannel, "bob's channel").to.not.be.undefined;

		// The negotiated type is taproot on both sides.
		expect(isTaprootChannel(aliceChannel.getFullState().channelType)).to.equal(
			true
		);
		expect(isTaprootChannel(bobChannel!.getFullState().channelType)).to.equal(
			true
		);

		// Both sides verified the peer's partial and advanced past funding.
		expect(aliceChannel.getFullState().state).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);
		expect(bobChannel!.getFullState().state).to.equal(
			ChannelState.AWAITING_FUNDING_CONFIRMED
		);

		// GATE: each side can aggregate the stored partials into a valid key-spend
		// signature over its own local commitment #0.
		assertAggregatesToValidKeySpend(aliceChannel);
		assertAggregatesToValidKeySpend(bobChannel!);
	});

	it('rejects a taproot funding_created carrying a corrupted partial', function () {
		const alice = new ChannelManager(makeConfig(3, true));
		const bob = new ChannelManager(makeConfig(4, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');

		// Intercept Alice→Bob and corrupt the partial sig inside funding_created (34).
		alice.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== bPub) return;
				let p = payload;
				if (type === 34) {
					// Flip a byte inside the appended partial_signature_with_nonce TLV
					// (after the 130-byte fixed body + 2-byte TLV header).
					p = Buffer.from(payload);
					p[p.length - 1] ^= 0xff;
				}
				bob.handleMessage(aPub, type, p);
			}
		);
		bob.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer === aPub) alice.handleMessage(bPub, type, payload);
			}
		);

		let bobError = false;
		bob.on('error', () => {
			bobError = true;
		});

		const aliceChannel = alice.openChannel(bPub, 1_000_000n);
		alice.createFunding(
			aliceChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);

		// Bob must NOT advance to AWAITING_FUNDING_CONFIRMED on a bad partial.
		const bobChannels = bob.getChannelsByPeer(aPub);
		for (const ch of bobChannels) {
			expect(ch.getFullState().state).to.not.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);
		}
		expect(bobError).to.equal(true);
	});

	it('an UNDECODABLE funding_created (truncated TLV) is refused on the wire, scoped to the temp id', function () {
		// A funding_created whose TLV suffix does not decode used to throw in
		// the codec and die in handleMessage's catch: a null-id local error,
		// nothing on the wire, the temp channel still tracked (the issue 415
		// shape at the decode boundary). The guard must take the exact refusal
		// the content arms use at SENT_ACCEPT: wire error scoped to the
		// temporary id, temp registration dropped, no funding_signed.
		const alice = new ChannelManager(makeConfig(5, true));
		const bob = new ChannelManager(makeConfig(6, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');

		let sentTempId: Buffer | null = null;
		const bobWire: Array<{ type: number; payload: Buffer }> = [];
		alice.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== bPub) return;
				let p = payload;
				if (type === MessageType.FUNDING_CREATED) {
					sentTempId = Buffer.from(payload.subarray(0, 32));
					// Keep the 130-byte fixed body, replace the partial TLV with
					// type 2 declaring 98 bytes and carrying 1: the decoder throws
					// before any handler content check runs.
					p = Buffer.concat([
						payload.subarray(0, 130),
						Buffer.from([0x02, 0x62, 0x01])
					]);
				}
				bob.handleMessage(aPub, type, p);
			}
		);
		bob.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				bobWire.push({ type, payload });
				if (peer === aPub) alice.handleMessage(bPub, type, payload);
			}
		);
		const bobErrors: Array<{ id: Buffer | null; message: string }> = [];
		bob.on('error', (id: Buffer | null, message: string) =>
			bobErrors.push({ id, message })
		);
		alice.on('error', () => undefined);

		const aliceChannel = alice.openChannel(bPub, 1_000_000n);
		alice.createFunding(
			aliceChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);

		expect(sentTempId, 'funding_created intercepted').to.not.equal(null);
		// The opener was told, scoped to the id it keys this negotiation by.
		const wireErrors = bobWire
			.filter((m) => m.type === MessageType.ERROR)
			.map((m) => decodeErrorMessage(m.payload));
		expect(wireErrors, 'exactly one wire error').to.have.length(1);
		expect(wireErrors[0].channelId.equals(sentTempId!)).to.equal(true);
		expect(wireErrors[0].data.toString('ascii')).to.contain(
			'Undecodable funding_created'
		);
		// No funding_signed for a message that never decoded.
		expect(bobWire.some((m) => m.type === MessageType.FUNDING_SIGNED)).to.equal(
			false
		);
		// The dead negotiation is unwound, and the local error names it by the
		// same id the wire refusal used.
		expect(bob.getTempChannel(sentTempId!)).to.equal(undefined);
		const refusal = bobErrors.find((e) =>
			e.message.includes('Undecodable funding_created')
		);
		expect(refusal, 'local refusal fired').to.not.equal(undefined);
		expect(refusal!.id, 'local error id present').to.not.equal(null);
		expect(refusal!.id!.equals(sentTempId!)).to.equal(true);
	});

	it('a refused funding_created reports the TEMPORARY id locally, never the peer-steered derived id', function () {
		// The permanent channel_id is derived from PEER-SUPPLIED fundingTxid
		// and fundingOutputIndex. Adopting it before verification meant an
		// opener quoting an all-zero txid at output 0 steered the LOCAL error
		// event to the all-zero id while the wire refusal correctly used the
		// temporary id. The derived id must not be adopted until every refusal
		// arm has passed.
		const alice = new ChannelManager(makeConfig(7, true));
		const bob = new ChannelManager(makeConfig(8, false));
		const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
		const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');

		const bobWire: Array<{ type: number; payload: Buffer }> = [];
		alice.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				if (peer !== bPub) return;
				let p = payload;
				if (type === MessageType.FUNDING_CREATED) {
					// Zero the fundingTxid (bytes 32..64); the output index stays 0,
					// so the derived channel_id is ALL-ZERO. The partial no longer
					// verifies over the zeroed outpoint, so bob refuses naturally.
					p = Buffer.from(payload);
					p.fill(0, 32, 64);
				}
				bob.handleMessage(aPub, type, p);
			}
		);
		bob.on(
			'message:outbound',
			(peer: string, type: number, payload: Buffer) => {
				bobWire.push({ type, payload });
				if (peer === aPub) alice.handleMessage(bPub, type, payload);
			}
		);
		const bobErrors: Array<{ id: Buffer | null; message: string }> = [];
		bob.on('error', (id: Buffer | null, message: string) =>
			bobErrors.push({ id, message })
		);
		alice.on('error', () => undefined);

		const aliceChannel = alice.openChannel(bPub, 1_000_000n);
		const tempId = aliceChannel.getTemporaryChannelId();
		alice.createFunding(
			aliceChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);

		const refusal = bobErrors.find((e) =>
			e.message.includes('Invalid taproot partial signature')
		);
		expect(refusal, 'local refusal fired').to.not.equal(undefined);
		// The local scope matches the wire scope: the temporary id, never the
		// all-zero derivation.
		expect(refusal!.id, 'local error id present').to.not.equal(null);
		expect(refusal!.id!.equals(tempId)).to.equal(true);
		const wireErrors = bobWire
			.filter((m) => m.type === MessageType.ERROR)
			.map((m) => decodeErrorMessage(m.payload));
		expect(wireErrors, 'exactly one wire error').to.have.length(1);
		expect(wireErrors[0].channelId.equals(tempId)).to.equal(true);
		expect(bobWire.some((m) => m.type === MessageType.FUNDING_SIGNED)).to.equal(
			false
		);
	});
});
