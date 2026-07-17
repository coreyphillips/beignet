/**
 * LOW-severity hardening batch (2026-07-15 review): BOLT 7 gossip/features,
 * watchtower justice output constraints, peer-storage privacy padding, and
 * the wallet bech32m validation. Each item is small and independent; grouped
 * into one PR.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	hasUnsupportedRequiredFeatures,
	implementedFeatures,
	FeatureFlags,
	Feature
} from '../../src/lightning/features/flags';
import { encodeNodeAnnouncementMessage } from '../../src/lightning/gossip/messages';
import { ADDRESS_TYPE_DNS } from '../../src/lightning/gossip/types';
import { buildJusticeBackup } from '../../src/lightning/watchtower/justice';
import { isValidBech32mEncodedString } from '../../src/utils/wallet';

describe('LOW hardening batch', function () {
	describe('BOLT 7 required-feature check vs the IMPLEMENTED set', function () {
		it('does not disconnect a peer requiring a feature we implement but did not advertise', function () {
			// route_blinding (24) and upfront_shutdown_script (4) are implemented
			// but not advertised in init; a peer requiring them must be accepted.
			const advertised = FeatureFlags.empty();
			const remote = FeatureFlags.empty();
			remote.setCompulsory(Feature.ROUTE_BLINDING);
			remote.setCompulsory(Feature.UPFRONT_SHUTDOWN_SCRIPT);
			expect(hasUnsupportedRequiredFeatures(advertised, remote)).to.have.length(
				0
			);
		});

		it('still disconnects a peer requiring a genuinely unknown feature', function () {
			const remote = FeatureFlags.empty();
			remote.setBit(100);
			expect(
				hasUnsupportedRequiredFeatures(FeatureFlags.empty(), remote)
			).to.deep.equal([100]);
		});

		it('implementedFeatures covers route_blinding and upfront_shutdown', function () {
			const impl = implementedFeatures();
			expect(impl.hasFeature(Feature.ROUTE_BLINDING)).to.equal(true);
			expect(impl.hasFeature(Feature.UPFRONT_SHUTDOWN_SCRIPT)).to.equal(true);
		});
	});

	describe('BOLT 7 node_announcement address rules', function () {
		const base = {
			signature: Buffer.alloc(64),
			features: Buffer.alloc(0),
			timestamp: 1,
			nodeId: Buffer.concat([Buffer.from([0x02]), crypto.randomBytes(32)]),
			rgbColor: Buffer.alloc(3),
			alias: Buffer.alloc(32)
		};

		it('rejects more than one DNS address', function () {
			expect(() =>
				encodeNodeAnnouncementMessage({
					...base,
					addresses: [
						{ type: ADDRESS_TYPE_DNS, host: 'a.example.com', port: 9735 },
						{ type: ADDRESS_TYPE_DNS, host: 'b.example.com', port: 9735 }
					]
				})
			).to.throw(/more than one DNS/);
		});

		it('accepts a single DNS address', function () {
			expect(() =>
				encodeNodeAnnouncementMessage({
					...base,
					addresses: [
						{ type: ADDRESS_TYPE_DNS, host: 'a.example.com', port: 9735 }
					]
				})
			).to.not.throw();
		});
	});

	describe('wallet bech32m validation (BIP-350)', function () {
		it('accepts a real P2TR address', function () {
			const res = isValidBech32mEncodedString(
				'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'
			);
			expect(res.isValid).to.equal(true);
			expect(res.network).to.equal('bitcoin');
		});

		it('rejects a well-checksummed string with an out-of-range program length', function () {
			// Valid bech32m checksum, witness v1, but 40-byte program (not 32):
			// v1 MUST be exactly 32, so this is not a valid taproot address.
			expect(
				isValidBech32mEncodedString(
					'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y'
				).isValid
			).to.equal(false);
		});

		it('does not treat a witness-v0 (bech32) address as bech32m', function () {
			expect(
				isValidBech32mEncodedString(
					'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
				).isValid
			).to.equal(false);
		});
	});

	describe('watchtower justice output constraints', function () {
		// Minimal context: only the sweep-script/dust guards are exercised, so a
		// stub revoked tx and keys are enough — buildJusticeTx runs before any
		// key derivation the guards would need.
		function ctxWithSweep(sweepScript: Buffer): unknown {
			const revoked = { getId: (): string => '11'.repeat(32), outs: [] };
			return {
				channelId: 'wt-low',
				revokedTx: revoked,
				perCommitmentSecret: crypto.randomBytes(32),
				revocationBasepoint: crypto.randomBytes(33),
				revocationBasepointSecret: crypto.randomBytes(32),
				remoteDelayedBasepoint: crypto.randomBytes(33),
				toSelfDelay: 144,
				isAnchor: false,
				sweepScript,
				network: undefined
			};
		}

		it('rejects a sweep script that is not 22 or 34 bytes', function () {
			expect(() =>
				buildJusticeBackup(
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					ctxWithSweep(Buffer.alloc(25)) as any,
					{ blobType: 0, sweepFeeRate: 2500n }
				)
			).to.throw(/22 or 34 bytes/);
		});
	});
});
