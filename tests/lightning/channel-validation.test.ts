import { expect } from 'chai';
import crypto from 'crypto';
import {
	deriveChannelId,
	generateTemporaryChannelId,
	validateOpenChannelParams,
	validateAcceptChannelParams,
	isValidShutdownScript
} from '../../src/lightning/channel/validation';
import {
	ChannelState,
	ChannelRole,
	HtlcDirection,
	HtlcState,
	MAX_ACCEPTED_HTLCS,
	MAX_FUNDING_SATOSHIS,
	MIN_DUST_LIMIT_SATOSHIS,
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IOpenChannelMessage } from '../../src/lightning/message/channel-open';
import { IAcceptChannelMessage } from '../../src/lightning/message/channel-open';

function fakePubkey(): Buffer {
	const buf = Buffer.alloc(33);
	buf[0] = 0x02;
	crypto.randomBytes(32).copy(buf, 1);
	return buf;
}

function makeValidOpenMsg(): IOpenChannelMessage {
	return {
		chainHash: BITCOIN_CHAIN_HASH,
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		channelReserveSatoshis: 10_000n,
		htlcMinimumMsat: 1_000n,
		feeratePerKw: 253,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		fundingPubkey: fakePubkey(),
		revocationBasepoint: fakePubkey(),
		paymentBasepoint: fakePubkey(),
		delayedPaymentBasepoint: fakePubkey(),
		htlcBasepoint: fakePubkey(),
		firstPerCommitmentPoint: fakePubkey(),
		channelFlags: 0x01
	};
}

function makeValidAcceptMsg(open: IOpenChannelMessage): IAcceptChannelMessage {
	return {
		temporaryChannelId: Buffer.from(open.temporaryChannelId),
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 500_000_000n,
		channelReserveSatoshis: 10_000n,
		htlcMinimumMsat: 1_000n,
		minimumDepth: 3,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 483,
		fundingPubkey: fakePubkey(),
		revocationBasepoint: fakePubkey(),
		paymentBasepoint: fakePubkey(),
		delayedPaymentBasepoint: fakePubkey(),
		htlcBasepoint: fakePubkey(),
		firstPerCommitmentPoint: fakePubkey()
	};
}

describe('Channel Types and Validation', function () {
	describe('Channel enums', function () {
		it('should have all expected channel states', function () {
			expect(ChannelState.NONE).to.equal('NONE');
			expect(ChannelState.SENT_OPEN).to.equal('SENT_OPEN');
			expect(ChannelState.NORMAL).to.equal('NORMAL');
			expect(ChannelState.CLOSED).to.equal('CLOSED');
			expect(ChannelState.ERRORED).to.equal('ERRORED');
		});

		it('should have opener and acceptor roles', function () {
			expect(ChannelRole.OPENER).to.equal('OPENER');
			expect(ChannelRole.ACCEPTOR).to.equal('ACCEPTOR');
		});

		it('should have HTLC directions', function () {
			expect(HtlcDirection.OFFERED).to.equal('OFFERED');
			expect(HtlcDirection.RECEIVED).to.equal('RECEIVED');
		});

		it('should have HTLC states', function () {
			expect(HtlcState.PENDING).to.equal('PENDING');
			expect(HtlcState.COMMITTED).to.equal('COMMITTED');
			expect(HtlcState.FULFILLED).to.equal('FULFILLED');
			expect(HtlcState.FAILED).to.equal('FAILED');
		});
	});

	describe('Constants', function () {
		it('should have correct max HTLCs', function () {
			expect(MAX_ACCEPTED_HTLCS).to.equal(483);
		});

		it('should have correct max funding', function () {
			expect(MAX_FUNDING_SATOSHIS).to.equal(16777216n);
		});

		it('should have correct min dust limit', function () {
			expect(MIN_DUST_LIMIT_SATOSHIS).to.equal(354n);
		});

		it('should have a valid default config', function () {
			expect(DEFAULT_CHANNEL_CONFIG.dustLimitSatoshis).to.equal(354n);
			expect(DEFAULT_CHANNEL_CONFIG.maxAcceptedHtlcs).to.equal(483);
			expect(DEFAULT_CHANNEL_CONFIG.feeratePerKw).to.equal(253);
		});

		it('should have correct bitcoin chain hash', function () {
			expect(BITCOIN_CHAIN_HASH.length).to.equal(32);
		});
	});

	describe('deriveChannelId', function () {
		it('should derive channel ID from funding txid and index 0', function () {
			const txid = Buffer.alloc(32, 0xaa);
			const channelId = deriveChannelId(txid, 0);
			// With index 0, XOR with 0 changes nothing
			expect(channelId).to.deep.equal(txid);
		});

		it('should XOR last 2 bytes with output index', function () {
			const txid = Buffer.alloc(32, 0x00);
			const channelId = deriveChannelId(txid, 1);
			// XOR last byte with 0x01
			expect(channelId[31]).to.equal(0x01);
			expect(channelId[30]).to.equal(0x00);
		});

		it('should handle output index with high byte', function () {
			const txid = Buffer.alloc(32, 0x00);
			const channelId = deriveChannelId(txid, 0x0100);
			expect(channelId[30]).to.equal(0x01);
			expect(channelId[31]).to.equal(0x00);
		});

		it('should handle output index 0xFFFF', function () {
			const txid = Buffer.alloc(32, 0x00);
			const channelId = deriveChannelId(txid, 0xffff);
			expect(channelId[30]).to.equal(0xff);
			expect(channelId[31]).to.equal(0xff);
		});

		it('should XOR correctly with non-zero txid', function () {
			const txid = Buffer.alloc(32, 0xff);
			const channelId = deriveChannelId(txid, 0x0102);
			// 0xFF ^ 0x01 = 0xFE, 0xFF ^ 0x02 = 0xFD
			expect(channelId[30]).to.equal(0xfe);
			expect(channelId[31]).to.equal(0xfd);
			// Other bytes unchanged
			expect(channelId[0]).to.equal(0xff);
			expect(channelId[29]).to.equal(0xff);
		});

		it('should not mutate the input txid', function () {
			const txid = Buffer.alloc(32, 0xab);
			const txidCopy = Buffer.from(txid);
			deriveChannelId(txid, 42);
			expect(txid).to.deep.equal(txidCopy);
		});

		it('should throw on wrong txid length', function () {
			expect(() => deriveChannelId(Buffer.alloc(16), 0)).to.throw('32 bytes');
		});

		it('should match known test vector', function () {
			// Known vector: txid all zeros, index 5
			const txid = Buffer.alloc(32, 0x00);
			const channelId = deriveChannelId(txid, 5);
			const expected = Buffer.alloc(32, 0x00);
			expected[31] = 0x05;
			expect(channelId).to.deep.equal(expected);
		});
	});

	describe('generateTemporaryChannelId', function () {
		it('should generate 32-byte buffer', function () {
			const id = generateTemporaryChannelId();
			expect(id.length).to.equal(32);
		});

		it('should generate unique IDs', function () {
			const id1 = generateTemporaryChannelId();
			const id2 = generateTemporaryChannelId();
			expect(id1.equals(id2)).to.be.false;
		});
	});

	describe('validateOpenChannelParams', function () {
		it('should accept valid params', function () {
			const msg = makeValidOpenMsg();
			expect(validateOpenChannelParams(msg)).to.be.null;
		});

		it('should reject zero funding_satoshis', function () {
			const msg = makeValidOpenMsg();
			msg.fundingSatoshis = 0n;
			expect(validateOpenChannelParams(msg)).to.contain('greater than 0');
		});

		it('should reject funding above max', function () {
			const msg = makeValidOpenMsg();
			msg.fundingSatoshis = MAX_FUNDING_SATOSHIS + 1n;
			expect(validateOpenChannelParams(msg)).to.contain('exceeds maximum');
		});

		it('should reject push_msat exceeding funding * 1000', function () {
			const msg = makeValidOpenMsg();
			msg.fundingSatoshis = 100_000n;
			msg.pushMsat = 100_000_001n;
			expect(validateOpenChannelParams(msg)).to.contain('push_msat');
		});

		it('should accept push_msat exactly funding * 1000', function () {
			const msg = makeValidOpenMsg();
			msg.fundingSatoshis = 100_000n;
			msg.pushMsat = 100_000_000n;
			expect(validateOpenChannelParams(msg)).to.be.null;
		});

		it('should reject dust_limit below minimum', function () {
			const msg = makeValidOpenMsg();
			msg.dustLimitSatoshis = 100n;
			expect(validateOpenChannelParams(msg)).to.contain('below minimum');
		});

		it('should reject max_accepted_htlcs above 483', function () {
			const msg = makeValidOpenMsg();
			msg.maxAcceptedHtlcs = 484;
			expect(validateOpenChannelParams(msg)).to.contain('exceeds maximum');
		});

		it('should reject channel_reserve below dust_limit', function () {
			const msg = makeValidOpenMsg();
			msg.channelReserveSatoshis = 400n;
			msg.dustLimitSatoshis = 546n;
			expect(validateOpenChannelParams(msg)).to.contain('channel_reserve');
		});

		it('should reject zero feerate_per_kw', function () {
			const msg = makeValidOpenMsg();
			msg.feeratePerKw = 0;
			expect(validateOpenChannelParams(msg)).to.contain('feerate_per_kw');
		});

		it('should reject zero to_self_delay', function () {
			const msg = makeValidOpenMsg();
			msg.toSelfDelay = 0;
			expect(validateOpenChannelParams(msg)).to.contain('to_self_delay');
		});

		it('should reject wrong pubkey length', function () {
			const msg = makeValidOpenMsg();
			msg.fundingPubkey = Buffer.alloc(32);
			expect(validateOpenChannelParams(msg)).to.contain('33 bytes');
		});
	});

	describe('validateAcceptChannelParams', function () {
		it('should accept valid params', function () {
			const open = makeValidOpenMsg();
			const accept = makeValidAcceptMsg(open);
			expect(validateAcceptChannelParams(open, accept)).to.be.null;
		});

		it('should reject mismatched temporary_channel_id', function () {
			const open = makeValidOpenMsg();
			const accept = makeValidAcceptMsg(open);
			accept.temporaryChannelId = crypto.randomBytes(32);
			expect(validateAcceptChannelParams(open, accept)).to.contain(
				'does not match'
			);
		});

		it('should reject dust_limit below minimum', function () {
			const open = makeValidOpenMsg();
			const accept = makeValidAcceptMsg(open);
			accept.dustLimitSatoshis = 100n;
			expect(validateAcceptChannelParams(open, accept)).to.contain(
				'below minimum'
			);
		});

		it('should reject max_accepted_htlcs above 483', function () {
			const open = makeValidOpenMsg();
			const accept = makeValidAcceptMsg(open);
			accept.maxAcceptedHtlcs = 484;
			expect(validateAcceptChannelParams(open, accept)).to.contain(
				'exceeds maximum'
			);
		});

		it('should reject acceptor reserve below opener dust', function () {
			const open = makeValidOpenMsg();
			open.dustLimitSatoshis = 1000n;
			const accept = makeValidAcceptMsg(open);
			accept.channelReserveSatoshis = 500n;
			expect(validateAcceptChannelParams(open, accept)).to.contain(
				'acceptor channel_reserve'
			);
		});

		it('should reject opener reserve below acceptor dust', function () {
			const open = makeValidOpenMsg();
			open.channelReserveSatoshis = 400n;
			const accept = makeValidAcceptMsg(open);
			accept.dustLimitSatoshis = 546n;
			expect(validateAcceptChannelParams(open, accept)).to.contain(
				'opener channel_reserve'
			);
		});

		it('should reject combined reserves exceeding funding', function () {
			const open = makeValidOpenMsg();
			open.fundingSatoshis = 20_000n;
			open.channelReserveSatoshis = 11_000n;
			const accept = makeValidAcceptMsg(open);
			accept.channelReserveSatoshis = 11_000n;
			expect(validateAcceptChannelParams(open, accept)).to.contain('combined');
		});

		it('should reject zero to_self_delay', function () {
			const open = makeValidOpenMsg();
			const accept = makeValidAcceptMsg(open);
			accept.toSelfDelay = 0;
			expect(validateAcceptChannelParams(open, accept)).to.contain(
				'to_self_delay'
			);
		});

		it('should reject wrong pubkey length', function () {
			const open = makeValidOpenMsg();
			const accept = makeValidAcceptMsg(open);
			accept.fundingPubkey = Buffer.alloc(32);
			expect(validateAcceptChannelParams(open, accept)).to.contain('33 bytes');
		});
	});

	describe('isValidShutdownScript (BOLT 2)', function () {
		const p2pkh = Buffer.concat([
			Buffer.from([0x76, 0xa9, 0x14]),
			Buffer.alloc(20),
			Buffer.from([0x88, 0xac])
		]);
		const p2sh = Buffer.concat([
			Buffer.from([0xa9, 0x14]),
			Buffer.alloc(20),
			Buffer.from([0x87])
		]);
		const p2wpkh = Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]);
		const p2wsh = Buffer.concat([Buffer.from([0x00, 0x20]), Buffer.alloc(32)]);
		const p2tr = Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32)]);

		it('accepts the standard non-segwit + segwit-v0 forms', function () {
			expect(isValidShutdownScript(p2pkh)).to.equal(true);
			expect(isValidShutdownScript(p2sh)).to.equal(true);
			expect(isValidShutdownScript(p2wpkh)).to.equal(true);
			expect(isValidShutdownScript(p2wsh)).to.equal(true);
		});

		it('rejects empty / junk / malformed scripts', function () {
			expect(isValidShutdownScript(Buffer.alloc(0))).to.equal(false);
			expect(isValidShutdownScript(Buffer.alloc(22))).to.equal(false); // 00 00 .. not P2WPKH
			expect(isValidShutdownScript(crypto.randomBytes(22))).to.equal(false);
			expect(
				isValidShutdownScript(Buffer.from([0x6a, 0x04, 1, 2, 3, 4]))
			).to.equal(false); // OP_RETURN
			expect(
				isValidShutdownScript(
					Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(19)])
				)
			).to.equal(false); // wrong len
		});

		it('gates other witness programs (P2TR) on option_shutdown_anysegwit', function () {
			expect(isValidShutdownScript(p2tr, false)).to.equal(false);
			expect(isValidShutdownScript(p2tr, true)).to.equal(true);
		});
	});
});
