/**
 * FFOR M6: liquidity integration (spec §11.3 + Appendix B.1 step 5).
 *
 * - FFOR standing-terms TLV (node_ann_tlvs 55007): codec round-trip and the
 *   S-side reject-if-outside-terms policy at ff_init.
 * - Lease-then-epoch: a bLIP-51 leased channel (S = lessor) runs a full FFOR
 *   epoch; escape commitments E_j carry the lease CLTV encumbrance on S's
 *   to_local (byte-level: leased E_j differs from unleased EXACTLY by the
 *   encumbered to_local script); the aggregate voucher is never encumbered;
 *   C_i^R vouchers are unaffected (S's balance is to_remote on R's
 *   commitment, which the lease encoding does not touch).
 * - leaseExpiry vs T_exp interplay: both orderings work.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	IFforTerms,
	encodeFforTerms,
	decodeFforTerms,
	NODE_ANN_TLV_FFOR_TERMS,
	FFOR_TERMS_LENGTH,
	ILeaseRates
} from '../../src/lightning/gossip/types';
import {
	encodeNodeAnnouncementMessage,
	decodeNodeAnnouncementMessage
} from '../../src/lightning/gossip/messages';
import { fforTermsViolation } from '../../src/lightning/ffor/epoch';
import {
	IEscapeChannelContext,
	buildEscapeCommitment
} from '../../src/lightning/ffor/escape';
import { buildToLocalScript } from '../../src/lightning/script/commitment';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { deriveCommitmentKeys } from '../../src/lightning/channel/commitment-builder';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { perCommitmentPointFromSecret } from '../../src/lightning/keys/derivation';
import { FforEpochState } from '../../src/lightning/ffor/types';
import { ChannelState } from '../../src/lightning/channel/types';
import {
	createTriple,
	goOffline,
	reconnectSR,
	pay,
	sha256,
	FUNDING_SATOSHIS,
	baseParamsA
} from './ffor-m6-harness';

const p2wsh = (script: Buffer): Buffer =>
	bitcoin.payments.p2wsh({ redeem: { output: script } }).output!;

// ─────────────── §11.3 terms TLV codec ───────────────

const TERMS: IFforTerms = {
	ffFeeBaseMsat: 1000,
	ffFeePpm: 5000,
	maxBudgetMsat: 100_000_000n,
	maxEpochBlocks: 4032,
	variants: 0b11 // A and B
};

describe('FFOR M6: standing-terms TLV (§11.3)', function () {
	it('encodes to 19 bytes and round-trips', function () {
		const buf = encodeFforTerms(TERMS);
		expect(buf.length).to.equal(FFOR_TERMS_LENGTH);
		expect(decodeFforTerms(buf)).to.deep.equal(TERMS);
	});

	it('uses odd TLV 55007 in the node_ann_tlvs stream', function () {
		expect(NODE_ANN_TLV_FFOR_TERMS).to.equal(55007n);
		expect(NODE_ANN_TLV_FFOR_TERMS % 2n).to.equal(1n); // ignorable
	});

	it('rides a node_announcement alongside lease_rates and round-trips', function () {
		const rates: ILeaseRates = {
			fundingWeightWitness: 666,
			leaseFeeBasis: 40,
			leaseFeeBaseSat: 500,
			channelFeeMaxBaseMsat: 5000,
			channelFeeMaxProportionalThousandths: 10
		};
		const payload = encodeNodeAnnouncementMessage({
			signature: Buffer.alloc(64, 1),
			features: Buffer.alloc(0),
			timestamp: 1_700_000_000,
			nodeId: getPublicKey(sha256(Buffer.from('m6-ann-node'))),
			rgbColor: Buffer.from([1, 2, 3]),
			alias: Buffer.alloc(32),
			addresses: [],
			leaseRates: rates,
			fforTerms: TERMS
		});
		const decoded = decodeNodeAnnouncementMessage(payload);
		expect(decoded.leaseRates).to.deep.equal(rates);
		expect(decoded.fforTerms).to.deep.equal(TERMS);
	});

	it('is absent (undefined) when not advertised', function () {
		const payload = encodeNodeAnnouncementMessage({
			signature: Buffer.alloc(64, 1),
			features: Buffer.alloc(0),
			timestamp: 1_700_000_000,
			nodeId: getPublicKey(sha256(Buffer.from('m6-ann-node2'))),
			rgbColor: Buffer.from([1, 2, 3]),
			alias: Buffer.alloc(32),
			addresses: []
		});
		expect(decodeNodeAnnouncementMessage(payload).fforTerms).to.equal(
			undefined
		);
	});

	it('fforTermsViolation covers each §11.3 rule', function () {
		const params = baseParamsA() as Parameters<typeof fforTermsViolation>[0];
		expect(fforTermsViolation(params, TERMS, 0)).to.equal(null);
		expect(
			fforTermsViolation(
				{ ...params, budgetMsat: TERMS.maxBudgetMsat + 1n },
				TERMS,
				0
			)
		).to.match(/max_budget_msat/);
		expect(
			fforTermsViolation({ ...params, feeBaseMsat: 999 }, TERMS, 0)
		).to.match(/ff_fee_base_msat/);
		expect(
			fforTermsViolation(
				{ ...params, feeProportionalMillionths: 4999 },
				TERMS,
				0
			)
		).to.match(/ff_fee_ppm/);
		expect(
			fforTermsViolation(params, { ...TERMS, variants: 0b10 }, 0)
		).to.match(/variant 1 not offered/);
		// Epoch length: D - height must be <= maxEpochBlocks (height known).
		expect(
			fforTermsViolation(params, { ...TERMS, maxEpochBlocks: 100 }, 500)
		).to.match(/max_epoch_blocks/);
		expect(
			fforTermsViolation(params, { ...TERMS, maxEpochBlocks: 500 }, 500)
		).to.equal(null);
	});
});

// ─────────────── §11.3 policy at ff_init (S side) ───────────────

describe('FFOR M6: advertised-terms policy at ff_init (§11.3)', function () {
	it('S accepts an ff_init echoing the advertised terms (R read the ad)', function () {
		// R "reads" the advertisement off the wire and echoes the terms.
		const ann = decodeNodeAnnouncementMessage(
			encodeNodeAnnouncementMessage({
				signature: Buffer.alloc(64, 1),
				features: Buffer.alloc(0),
				timestamp: 1,
				nodeId: getPublicKey(sha256(Buffer.from('m6-s-ad'))),
				rgbColor: Buffer.alloc(3),
				alias: Buffer.alloc(32),
				addresses: [],
				fforTerms: TERMS
			})
		);
		const ad = ann.fforTerms!;
		const t = createTriple({
			prefix: 'terms-ok',
			sConfigOverrides: { fforTerms: TERMS },
			params: {
				feeBaseMsat: ad.ffFeeBaseMsat,
				feeProportionalMillionths: ad.ffFeePpm,
				budgetMsat: ad.maxBudgetMsat
			}
		});
		expect(t.sChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_EPOCH);
		expect(t.rChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_EPOCH);
	});

	const rejectCase = (
		name: string,
		params: Record<string, unknown>,
		errRe: RegExp
	): void => {
		it(`S rejects ff_init ${name}`, function () {
			const t = createTriple({
				prefix: 'terms-rej',
				noEpoch: true,
				sConfigOverrides: { fforTerms: TERMS }
			});
			const res = t.rManager.initiateFforEpoch(t.srChannelId, {
				...baseParamsA(),
				...params
			});
			// R's local pre-validation passes; S's terms policy rejects with
			// ff_error, which aborts R's setup.
			expect(res.ok).to.equal(true);
			expect(
				t.sErrors.some((e) => e.includes('outside advertised FFOR terms')),
				t.sErrors.join('; ')
			).to.equal(true);
			expect(t.sErrors.join('; ')).to.match(errRe);
			expect(t.sChannel.getFforEpoch()).to.equal(null);
			// R aborted cleanly and the channel is reusable: a compliant epoch
			// then establishes.
			expect(t.rChannel.getState()).to.equal(ChannelState.NORMAL);
			const retry = t.rManager.initiateFforEpoch(t.srChannelId, baseParamsA());
			expect(retry.ok, t.rErrors.join('; ')).to.equal(true);
			expect(t.sChannel.getFforEpoch()!.state).to.equal(
				FforEpochState.FF_EPOCH
			);
		});
	};

	rejectCase(
		'over the advertised max budget',
		{ budgetMsat: TERMS.maxBudgetMsat + 1_000n },
		/max_budget_msat/
	);
	rejectCase(
		'under-pricing the advertised base fee',
		{ feeBaseMsat: TERMS.ffFeeBaseMsat - 1 },
		/ff_fee_base_msat/
	);
	rejectCase(
		'under-pricing the advertised proportional fee',
		{ feeProportionalMillionths: TERMS.ffFeePpm - 1 },
		/ff_fee_ppm/
	);

	it('S rejects a variant its advertisement does not offer', function () {
		const t = createTriple({
			prefix: 'terms-var',
			noEpoch: true,
			sConfigOverrides: {
				fforTerms: { ...TERMS, variants: 0b10 } // B only
			}
		});
		const res = t.rManager.initiateFforEpoch(
			t.srChannelId,
			baseParamsA() // variant A
		);
		expect(res.ok).to.equal(true);
		expect(t.sErrors.join('; ')).to.match(/variant 1 not offered/);
		expect(t.sChannel.getFforEpoch()).to.equal(null);
	});

	it('S rejects an epoch longer than advertised (height-aware)', function () {
		const t = createTriple({
			prefix: 'terms-len',
			noEpoch: true,
			sConfigOverrides: {
				fforTerms: { ...TERMS, maxEpochBlocks: 100 }
			}
		});
		t.sManager.handleNewBlock(500);
		t.rManager.handleNewBlock(500);
		const res = t.rManager.initiateFforEpoch(t.srChannelId, {
			...baseParamsA(),
			settlementDeadline: 1000, // 500 blocks out > 100 advertised
			voucherExpiry: 2008
		});
		expect(res.ok).to.equal(true);
		expect(t.sErrors.join('; ')).to.match(/max_epoch_blocks/);
		expect(t.sChannel.getFforEpoch()).to.equal(null);
	});
});

// ─────────────── B.1 step 5: lease encumbrance on E_j ───────────────

const LEASE_EXPIRY = 4500;
const G = 50_000_000n;

function escapeFixtureCtx(leased: boolean): IEscapeChannelContext {
	const bp = (tag: string): IChannelBasepoints => {
		const k = (i: number): Buffer =>
			sha256(Buffer.from(`m6-lease-${tag}-${i}`));
		return {
			fundingPubkey: getPublicKey(k(0)),
			revocationBasepoint: getPublicKey(k(1)),
			paymentBasepoint: getPublicKey(k(2)),
			delayedPaymentBasepoint: getPublicKey(k(3)),
			htlcBasepoint: getPublicKey(k(4)),
			firstPerCommitmentPoint: Buffer.alloc(33)
		};
	};
	const sSeed = sha256(Buffer.from('m6-lease-S-seed'));
	const n0 = 7n;
	return {
		fundingTxid: sha256(Buffer.from('m6-lease-funding')),
		fundingOutputIndex: 0,
		fundingSatoshis: 1_000_000n,
		sIsOpener: true,
		sBasepoints: bp('S'),
		rBasepoints: bp('R'),
		sPerCommitmentPointN0Plus1: perCommitmentPointFromSecret(
			generateFromSeed(sSeed, MAX_INDEX - (n0 + 1n))
		),
		n0,
		preEpochSLocalMsat: 1_000_000_000n,
		preEpochRLocalMsat: 0n,
		sToSelfDelay: 144,
		frozenFeeratePerKw: 2500,
		voucherExpiry: 2008,
		sLeaseExpiry: leased ? LEASE_EXPIRY : undefined
	};
}

describe('FFOR M6: lease encumbrance on escapes (B.1 step 5)', function () {
	it('a leased E_j differs from unleased EXACTLY by the encumbered to_local', function () {
		const leased = buildEscapeCommitment(escapeFixtureCtx(true), 1, G);
		const plain = buildEscapeCommitment(escapeFixtureCtx(false), 1, G);

		// Same output count and identical value multisets.
		expect(leased.tx.outs.length).to.equal(plain.tx.outs.length);
		const values = (tx: bitcoin.Transaction): string =>
			tx.outs
				.map((o) => o.value.toString())
				.sort()
				.join(',');
		expect(values(leased.tx)).to.equal(values(plain.tx));

		// The aggregate voucher (an R output) is NEVER lease-encumbered:
		// identical script and value in both.
		expect(leased.voucherScript.equals(plain.voucherScript)).to.equal(true);
		expect(leased.voucherValueSat).to.equal(plain.voucherValueSat);
		expect(
			Buffer.from(leased.tx.outs[leased.voucherOutputIndex].script).equals(
				p2wsh(leased.voucherScript)
			)
		).to.equal(true);

		// Exactly ONE output script differs between the two: S's to_local.
		const scriptsL = leased.tx.outs.map((o) => Buffer.from(o.script));
		const scriptsP = plain.tx.outs.map((o) => Buffer.from(o.script));
		const onlyInLeased = scriptsL.filter(
			(s) => !scriptsP.some((q) => q.equals(s))
		);
		const onlyInPlain = scriptsP.filter(
			(s) => !scriptsL.some((q) => q.equals(s))
		);
		expect(onlyInLeased.length).to.equal(1);
		expect(onlyInPlain.length).to.equal(1);

		// And the leased one is EXACTLY the lease-encumbered BOLT 3 to_local:
		// `<lease_expiry> CLTV DROP` prepended to the CSV delay branch.
		const keys = deriveCommitmentKeys(
			escapeFixtureCtx(true).sBasepoints,
			escapeFixtureCtx(true).rBasepoints,
			escapeFixtureCtx(true).sPerCommitmentPointN0Plus1,
			true
		);
		const toLocalLeased = buildToLocalScript(
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			144,
			LEASE_EXPIRY
		);
		const toLocalPlain = buildToLocalScript(
			keys.revocationPubkey,
			keys.localDelayedPubkey,
			144
		);
		expect(onlyInLeased[0].equals(p2wsh(toLocalLeased))).to.equal(true);
		expect(onlyInPlain[0].equals(p2wsh(toLocalPlain))).to.equal(true);
	});

	it('leased channel: epoch with escapes establishes (both sides derive the encumbered set byte-identically) and E_j carries the lease lock', function () {
		const t = createTriple({
			prefix: 'lease-esc',
			lease: { expiry: LEASE_EXPIRY },
			params: { escapeGranularityMsat: G }
		});
		// Setup succeeded: S verified R's signatures over the LEASED escape
		// set — if either side had omitted the encumbrance the sigs would not
		// verify and the epoch would have been refused.
		expect(t.sChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_EPOCH);
		expect(t.sChannel.getFforEpoch()!.escapeSigs).to.have.length(2);
		expect(t.sChannel.getFforEpoch()!.sLeaseExpiry).to.equal(LEASE_EXPIRY);
		expect(t.rChannel.getFforEpoch()!.sLeaseExpiry).to.equal(LEASE_EXPIRY);

		// S's broadcast-ready E_1 contains the lease-encumbered to_local.
		const built = t.sChannel.fforBuildEscapeForBroadcast(1);
		expect(built.ok, built.error).to.equal(true);
		const tx = bitcoin.Transaction.fromHex(built.txHex!);
		const sPoint = t.rChannel.getFullState().remoteNextPerCommitmentPoint!;
		const keys = deriveCommitmentKeys(
			t.sConfig.localBasepoints,
			t.rConfig.localBasepoints,
			sPoint,
			true
		);
		const toLocalLeased = p2wsh(
			buildToLocalScript(
				keys.revocationPubkey,
				keys.localDelayedPubkey,
				6, // R's toSelfDelay requirement of S
				LEASE_EXPIRY
			)
		);
		expect(
			tx.outs.some((o) => Buffer.from(o.script).equals(toLocalLeased)),
			'E_1 to_local carries the lease CLTV encumbrance'
		).to.equal(true);
	});

	it('full epoch on a leased channel: settlement, reconcile, and voucher conversion produce the same balances as unleased (C_i^R untouched by the lease)', function () {
		const run = (leased: boolean): bigint[] => {
			const t = createTriple({
				prefix: leased ? 'lease-flow' : 'plain-flow',
				lease: leased ? { expiry: LEASE_EXPIRY } : undefined
			});
			goOffline(t);
			pay(t, t.hashes[0], 1_000_000n);
			pay(t, t.hashes[1], 50_000_000n);
			expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
			reconnectSR(t);
			expect(
				t.rChannel.getFforEpoch()!.state,
				t.rErrors.concat(t.sErrors).join('; ')
			).to.equal(FforEpochState.FF_CLOSED);
			const fulfill = t.rManager.fforFulfillVouchers(t.srChannelId);
			expect(fulfill.ok).to.equal(true);
			return [
				t.rChannel.getBalances().localMsat,
				t.sChannel.getBalances().localMsat
			];
		};
		const leasedBalances = run(true);
		const plainBalances = run(false);
		expect(leasedBalances).to.deep.equal(plainBalances);
		// v_1 + v_2 = (1,000,000 - 6,000) + (50,000,000 - 251,000)
		expect(leasedBalances[0]).to.equal(994_000n + 49_749_000n);
		expect(leasedBalances[1]).to.equal(
			FUNDING_SATOSHIS * 1000n - 994_000n - 49_749_000n
		);
	});

	it('leaseExpiry on either side of T_exp: epoch establishes and escapes rebuild (sanity)', function () {
		for (const expiry of [1500 /* < T_exp = 2008 */, 4500 /* > T_exp */]) {
			const t = createTriple({
				prefix: `lease-texp-${expiry}`,
				lease: { expiry },
				params: { escapeGranularityMsat: G }
			});
			expect(t.sChannel.getFforEpoch()!.state, t.sErrors.join('; ')).to.equal(
				FforEpochState.FF_EPOCH
			);
			const built = t.sChannel.fforBuildEscapeForBroadcast(2);
			expect(built.ok, built.error).to.equal(true);
		}
	});
});
