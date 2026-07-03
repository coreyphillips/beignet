/**
 * FFOR Appendix A cross-check (specs/ffor-test-vectors.md): reproduce the
 * canonical C_1..C_3 scenario through the M2 settlement engine
 * (src/lightning/ffor/settlement.ts) and assert the commitment txids,
 * commitment signatures, and HTLC signatures equal the published vectors
 * byte-exactly. This pins the engine to the spec's canonical bytes: any
 * construction drift (ordering, trimming, remainders, sighash) fails here.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	createOpenerState,
	createAcceptorState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	IChannelConfig
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { ChannelSigner } from '../../src/lightning/keys/signer';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	FforEpochState,
	FforVariant,
	IFforEpochStateData
} from '../../src/lightning/ffor/types';
import {
	buildSettlementPackage,
	buildVoucherCommitment,
	buildVoucherCommitmentLocal,
	validateSettlementPackage,
	fforSkimFeeMsat
} from '../../src/lightning/ffor/settlement';
import { decodeFforSettlementMessage } from '../../src/lightning/ffor/messages';

const h2b = (s: string): Buffer => Buffer.from(s, 'hex');
const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

// ── A.1 fixture material (BOLT 3 Appendix C + documented SHA256 tags) ──

const R_FUNDING_PRIV = h2b(
	'30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749'
);
const S_FUNDING_PRIV = h2b(
	'1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13'
);
const R_PAYMENT_SECRET = h2b(
	'1111111111111111111111111111111111111111111111111111111111111111'
);
const S_REVOCATION_SECRET = h2b(
	'2222222222222222222222222222222222222222222222222222222222222222'
);
const R_DELAYED_SECRET = h2b(
	'3333333333333333333333333333333333333333333333333333333333333333'
);
const S_PAYMENT_SECRET = h2b(
	'4444444444444444444444444444444444444444444444444444444444444444'
);
const R_REVOCATION_SECRET = sha256(
	Buffer.from('ffor/R/revocation-basepoint-secret')
);
const S_DELAYED_SECRET = sha256(
	Buffer.from('ffor/S/delayed-payment-basepoint-secret')
);
const R_PC_SEED = sha256(Buffer.from('ffor/R/per-commitment-seed'));
const S_PC_SEED = sha256(Buffer.from('ffor/S/per-commitment-seed'));

const FUNDING_TXID_INTERNAL = h2b(
	'bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489'
);
const N_R = 42n;
const N0 = 42n;
const T_EXP = 800_000;
const FEERATE = 2500;

function pcSecret(seed: Buffer, n: bigint): Buffer {
	return generateFromSeed(seed, MAX_INDEX - n);
}
function pcPoint(seed: Buffer, n: bigint): Buffer {
	return perCommitmentPointFromSecret(pcSecret(seed, n));
}

const rBasepoints: IChannelBasepoints = {
	fundingPubkey: getPublicKey(R_FUNDING_PRIV),
	revocationBasepoint: getPublicKey(R_REVOCATION_SECRET),
	paymentBasepoint: getPublicKey(R_PAYMENT_SECRET),
	delayedPaymentBasepoint: getPublicKey(R_DELAYED_SECRET),
	htlcBasepoint: getPublicKey(R_PAYMENT_SECRET),
	firstPerCommitmentPoint: pcPoint(R_PC_SEED, 0n)
};
const sBasepoints: IChannelBasepoints = {
	fundingPubkey: getPublicKey(S_FUNDING_PRIV),
	revocationBasepoint: getPublicKey(S_REVOCATION_SECRET),
	paymentBasepoint: getPublicKey(S_PAYMENT_SECRET),
	delayedPaymentBasepoint: getPublicKey(S_DELAYED_SECRET),
	htlcBasepoint: getPublicKey(S_PAYMENT_SECRET),
	firstPerCommitmentPoint: pcPoint(S_PC_SEED, 0n)
};

const channelTypeFlags = FeatureFlags.empty();
channelTypeFlags.setCompulsory(Feature.STATIC_REMOTE_KEY);
channelTypeFlags.setCompulsory(Feature.ANCHOR_ZERO_FEE_HTLC);
const CHANNEL_TYPE = channelTypeFlags.toBuffer();

const CONFIG: IChannelConfig = {
	dustLimitSatoshis: 546n,
	maxHtlcValueInFlightMsat: 5_000_000_000n,
	channelReserveSatoshis: 10_000n,
	htlcMinimumMsat: 1n,
	toSelfDelay: 144,
	maxAcceptedHtlcs: 483,
	feeratePerKw: FEERATE
};

function makeSState(): IChannelState {
	const st = createOpenerState({
		temporaryChannelId: Buffer.alloc(32),
		fundingSatoshis: 10_000_000n,
		pushMsat: 3_000_000_000n,
		localConfig: { ...CONFIG },
		localBasepoints: sBasepoints,
		localPerCommitmentSeed: S_PC_SEED
	});
	st.remoteBasepoints = rBasepoints;
	st.remoteConfig = { ...CONFIG };
	st.fundingTxid = FUNDING_TXID_INTERNAL;
	st.fundingOutputIndex = 0;
	st.channelType = CHANNEL_TYPE;
	st.state = ChannelState.NORMAL;
	st.localCommitmentNumber = N0;
	st.remoteCommitmentNumber = N_R;
	return st;
}

function makeRState(): IChannelState {
	const st = createAcceptorState({
		temporaryChannelId: Buffer.alloc(32),
		fundingSatoshis: 10_000_000n,
		pushMsat: 3_000_000_000n,
		localConfig: { ...CONFIG },
		localBasepoints: rBasepoints,
		localPerCommitmentSeed: R_PC_SEED,
		remoteBasepoints: sBasepoints,
		remoteConfig: { ...CONFIG }
	});
	st.fundingTxid = FUNDING_TXID_INTERNAL;
	st.fundingOutputIndex = 0;
	st.channelType = CHANNEL_TYPE;
	st.state = ChannelState.NORMAL;
	st.localCommitmentNumber = N_R;
	st.remoteCommitmentNumber = N0;
	return st;
}

// ── A.2: payments, preimages, hashes ──

const P1 = pcSecret(S_PC_SEED, N0); // per_commitment_secret_S[42]
const PREIMAGES = [P1, Buffer.alloc(32, 0x02), Buffer.alloc(32, 0x03)];
const HTLC_AMOUNTS = [1_000_000n, 550_000n, 50_000_000n];

function makeEpoch(role: 'settlement_peer' | 'recipient'): IFforEpochStateData {
	return {
		epochId: Buffer.alloc(32, 0xee),
		role,
		state: FforEpochState.FF_EPOCH,
		params: {
			variant: FforVariant.A,
			budgetMsat: 100_000_000n,
			maxPayments: 8,
			minPaymentMsat: 10_000n,
			settlementDeadline: 799_000,
			voucherExpiry: T_EXP,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 5000,
			escapeGranularityMsat: 0n,
			rPerCommitmentPoints: Array.from({ length: 8 }, (_, i) =>
				pcPoint(R_PC_SEED, N_R + BigInt(i + 1))
			),
			paymentHashes: PREIMAGES.map(sha256)
		},
		sCommitmentNumber: N0,
		invoices: [],
		escapeSigs: [],
		escapeHtlcSigs: [],
		initSignature: null,
		acceptSignature: null,
		remoteNodeId: null,
		epochStartHeight: null,
		preimages: role === 'settlement_peer' ? PREIMAGES.map(Buffer.from) : [],
		lastSeq: 0,
		packages: [],
		htlcAmountsMsat: [],
		voucherAmountsMsat: [],
		upstreamFulfilled: [],
		upstreamHtlcIds: [],
		sHtlcIdBase: 0n,
		frozenFeeratePerKw: FEERATE,
		nR: N_R,
		rPreEpochPoint: pcPoint(R_PC_SEED, N_R),
		peerLastSeq: null
	};
}

// ── Published vectors (specs/ffor-test-vectors.md A.3) ──

const VECTORS = [
	{
		txid: '5d7e2c85156d35024911820bcdcf0ce410057639165a7ef12b33ea3687a10bfb',
		commitSig:
			'6d2d86677f1656b7cf63516c0b542d7dad5341f0e88f036b3bb221b23200e5ed4dd125fa8ceb6ae9d22893553e4beabaa31a4e3f56447ef309fcc9120ad4eeb8',
		htlcSigs: [
			'dee0d8437159468b0b67941cf3df7a876271d05f58b7885d9554a6197945eb22701b0aecefacaf7831b62f241d1a1698c1d28729fa1e9ab6b88e9f24a7fdd24f'
		]
	},
	{
		txid: '8d0d39d5f194be5a83b673206076fd86c1542b5861cda4d04cd3eaa6f38b5634',
		commitSig:
			'd15b2fbdb880b6a452c08d9e38f4b6e60020adb00ef70707b7e3ed7dc74afb35201b622b5ae4d68117c09bc8bfc641275ffec5349a183bfa1cd7fd91a03042c9',
		htlcSigs: [
			// BOLT 3 output-index order: voucher 2 (546 sat) sorts BEFORE voucher 1.
			'4f04d239e841ee892fe61eafcf6a1d11c7e83356c5e2f325708da089d5909a2a1a9c59fb8b2157564641fffbad1ef9379b26ffa68e600c440195639b69a77287',
			'6db331b2bba37bc22b8ceaf3c199843a1f268061019be24077a0809aea7d4dc945e5c10a3ee058154c50048fa0ee130c936b0e7335614a6dd90ad57f54ca79fb'
		]
	},
	{
		txid: '237d464440a2ad7b5e80f10307cdcee57545c0b51fcde5619c56c170285f9c8b',
		commitSig:
			'596641c99683b7484dbdf98f6c64df41e5a40d562ae66c767231ff9d5bd2d6e67594260fa308e1cfffdd6c7f570fc5fad922a2a3f0103f9800aa3b98b976725d',
		htlcSigs: [
			// Output order: voucher 2 (546), voucher 1 (994), voucher 3 (49749).
			'8371216a9a675a69592d08dbc5bfbed45c26bef7394a1a49dbe0c98fcc23236e13e03c2a16938658149142d820efb8b2cca9d1fb4c0a5e6935a99791baae7034',
			'196d0d67f5b688ad7cf4c866efde492253e8e7af20436c5557c7c7c6c86f0de36c4c17ebb10aec4d6535aa841c3460a5c9a20ad5f67282e6c89438eff29e7caf',
			'c8b824d74c765f51e2fa4dbb737fad2337dcf66ddfefa6fc7a5467543108574a01ce87211237d0f12015602bda4451b6615c95b4e9d4224371811e828f76b50a'
		]
	}
];

const C0_TXID =
	'f432e2a8d9c1066c1127eb5367e147719f4810b66f43e15809f40f21a111eee9';

describe('FFOR Appendix A vector cross-check (M2 engine)', function () {
	it('fixture keys re-derive the Appendix C pubkeys and H_1 binding', function () {
		expect(rBasepoints.fundingPubkey.toString('hex')).to.equal(
			'023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb'
		);
		expect(sBasepoints.fundingPubkey.toString('hex')).to.equal(
			'030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1'
		);
		// FFOR §7.2 variant-A binding.
		expect(sha256(P1).toString('hex')).to.equal(
			'e4436ccb23764c40624d579e288c09f8da56f0994b1d54cd44c4f9d7923bfe96'
		);
		expect(getPublicKey(P1).toString('hex')).to.equal(
			'03f40c57917588ccad5793436f38e4a62c2f41892bd02b2f72c441163056c71029'
		);
	});

	it('reproduces C_0 (pre-epoch base state) byte-exactly', function () {
		const epoch = makeEpoch('settlement_peer');
		const built = buildVoucherCommitment(makeSState(), epoch, 0);
		expect(built.result.tx.getId()).to.equal(C0_TXID);
	});

	it('reproduces C_1..C_3 packages: txids, commitment sigs, htlc sigs (output-index order)', function () {
		const sState = makeSState();
		const sSigner = new ChannelSigner(S_FUNDING_PRIV, S_PAYMENT_SECRET);
		const epoch = makeEpoch('settlement_peer');
		const nodeKey = sha256(Buffer.from('ffor/S/node-key'));
		const { sign } = require('../../src/lightning/crypto/ecdh');

		for (let seq = 1; seq <= 3; seq++) {
			// The engine records the amounts, then builds + signs the package.
			epoch.htlcAmountsMsat[seq - 1] = HTLC_AMOUNTS[seq - 1];
			epoch.voucherAmountsMsat[seq - 1] =
				HTLC_AMOUNTS[seq - 1] - fforSkimFeeMsat(epoch, HTLC_AMOUNTS[seq - 1]);
			const { payload } = buildSettlementPackage({
				base: sState,
				signer: sSigner,
				epoch,
				channelId: Buffer.alloc(32, 0xcc),
				seq,
				signFn: (digest: Buffer): Buffer => sign(digest, nodeKey)
			});
			epoch.packages[seq - 1] = payload;
			epoch.lastSeq = seq;

			const vec = VECTORS[seq - 1];
			const msg = decodeFforSettlementMessage(payload);

			// The commitment S signed is the published one, byte-for-byte.
			const built = buildVoucherCommitment(sState, epoch, seq);
			expect(built.result.tx.getId(), `C_${seq} txid`).to.equal(vec.txid);

			// BOLT 2 compact signatures match the vectors exactly (RFC 6979).
			expect(msg.commitmentSig.toString('hex'), `C_${seq} commit sig`).to.equal(
				vec.commitSig
			);
			expect(msg.htlcSigs.length).to.equal(seq);
			for (let k = 0; k < seq; k++) {
				expect(
					msg.htlcSigs[k].toString('hex'),
					`C_${seq} htlc_sig[${k}]`
				).to.equal(vec.htlcSigs[k]);
			}

			// Voucher values match A.2 (sub-satoshi remainder rule included).
			expect(msg.voucherAmountMsat).to.equal(
				[994_000n, 546_250n, 49_749_000n][seq - 1]
			);
		}
	});

	it('R rebuilds each C_i byte-identically and accepts each package (§9.4 checklist)', function () {
		const sState = makeSState();
		const rState = makeRState();
		const sSigner = new ChannelSigner(S_FUNDING_PRIV, S_PAYMENT_SECRET);
		const rSigner = new ChannelSigner(R_FUNDING_PRIV, R_PAYMENT_SECRET);
		const sEpoch = makeEpoch('settlement_peer');
		const rEpoch = makeEpoch('recipient');
		const nodeKey = sha256(Buffer.from('ffor/S/node-key'));
		const nodeId = getPublicKey(nodeKey);
		const { sign } = require('../../src/lightning/crypto/ecdh');

		for (let seq = 1; seq <= 3; seq++) {
			sEpoch.htlcAmountsMsat[seq - 1] = HTLC_AMOUNTS[seq - 1];
			sEpoch.voucherAmountsMsat[seq - 1] =
				HTLC_AMOUNTS[seq - 1] - fforSkimFeeMsat(sEpoch, HTLC_AMOUNTS[seq - 1]);
			const { payload } = buildSettlementPackage({
				base: sState,
				signer: sSigner,
				epoch: sEpoch,
				channelId: Buffer.alloc(32, 0xcc),
				seq,
				signFn: (digest: Buffer): Buffer => sign(digest, nodeKey)
			});
			sEpoch.lastSeq = seq;

			// Full §9.4 validation from R's mirror state (records the amounts).
			const result = validateSettlementPackage({
				base: rState,
				signer: rSigner,
				epoch: rEpoch,
				payload,
				remoteNodeId: nodeId,
				sPerCommitmentPointN0: pcPoint(S_PC_SEED, N0),
				currentBlockHeight: 0
			});
			expect(result.ok, `package ${seq}: ${result.error ?? ''}`).to.equal(true);
			rEpoch.lastSeq = seq;
			rEpoch.preimages[seq - 1] = result.msg!.preimage!;

			// R-side byte-identical rebuild (Appendix A verification 2).
			const local = buildVoucherCommitmentLocal(rState, rEpoch, seq);
			expect(local.result.tx.getId()).to.equal(VECTORS[seq - 1].txid);
		}
		// Every preimage recovered matches the published set.
		for (let k = 0; k < 3; k++) {
			expect(rEpoch.preimages[k].equals(PREIMAGES[k])).to.equal(true);
		}
	});

	it('a tampered package fails R validation', function () {
		const sState = makeSState();
		const rState = makeRState();
		const sSigner = new ChannelSigner(S_FUNDING_PRIV, S_PAYMENT_SECRET);
		const rSigner = new ChannelSigner(R_FUNDING_PRIV, R_PAYMENT_SECRET);
		const sEpoch = makeEpoch('settlement_peer');
		const rEpoch = makeEpoch('recipient');
		const nodeKey = sha256(Buffer.from('ffor/S/node-key'));
		const { sign } = require('../../src/lightning/crypto/ecdh');

		sEpoch.htlcAmountsMsat[0] = HTLC_AMOUNTS[0];
		sEpoch.voucherAmountsMsat[0] =
			HTLC_AMOUNTS[0] - fforSkimFeeMsat(sEpoch, HTLC_AMOUNTS[0]);
		const { payload } = buildSettlementPackage({
			base: sState,
			signer: sSigner,
			epoch: sEpoch,
			channelId: Buffer.alloc(32, 0xcc),
			seq: 1,
			signFn: (digest: Buffer): Buffer => sign(digest, nodeKey)
		});
		const tampered = Buffer.from(payload);
		tampered[80] ^= 0x01; // corrupt a signed body byte
		const result = validateSettlementPackage({
			base: rState,
			signer: rSigner,
			epoch: rEpoch,
			payload: tampered,
			remoteNodeId: getPublicKey(nodeKey),
			sPerCommitmentPointN0: pcPoint(S_PC_SEED, N0),
			currentBlockHeight: 0
		});
		expect(result.ok).to.equal(false);
		expect(result.error).to.include('node-key signature invalid');
	});
});
