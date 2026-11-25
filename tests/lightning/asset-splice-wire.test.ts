import { expect } from 'chai';
import {
	assetSpliceCommitmentBytes,
	assetSpliceNegotiated
} from '../../src/lightning/features/asset-splice';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { encodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { MAX_LIGHTNING_PAYLOAD } from '../../src/lightning/message/custom-records';
import {
	ASSET_OPENING_TYPE_HEX,
	ASSET_SPLICE_RECOVERY_TYPE_HEX,
	assetOpeningNegotiated
} from '../../src/lightning/features/asset-opening';

import { completeAssetSpliceRecoveryHost } from '../../src/lightning/channel/asset-splice-update-transport';

describe('Asset splice admission on each commitment wire', () => {
	const records = [
		{ type: 65537n, maxBytes: 54615 },
		{ type: 65553n, maxBytes: 66 }
	];
	it('refuses the measured grouped profile after adding the explicit funding tag', () => {
		const parts = {
			channelId: Buffer.alloc(32),
			signature: Buffer.alloc(64),
			partialSignatureWithNonce: Buffer.alloc(98),
			htlcSignatures: Array.from({ length: 166 }, () => Buffer.alloc(64)),
			customRecords: new Map(
				records.map((v) => [v.type, Buffer.alloc(v.maxBytes)])
			)
		};
		expect(encodeCommitmentSignedMessage(parts)).to.have.length(65517);
		expect(() =>
			encodeCommitmentSignedMessage({ ...parts, fundingTxid: Buffer.alloc(32) })
		).to.throw();
		expect(() => assetSpliceCommitmentBytes([83, 83], records)).to.throw(
			/65551/
		);
		expect(assetSpliceCommitmentBytes([83, 83], [records[0]])).to.equal(65479);
	});
	it('accounts for every negotiated record including boundaries in length and type encoding', () => {
		for (const width of [1, 252, 253, 1000, 2000]) {
			const record = { type: 65537n, maxBytes: width };
			const expected = encodeCommitmentSignedMessage({
				channelId: Buffer.alloc(32),
				signature: Buffer.alloc(64),
				htlcSignatures: Array.from({ length: 17 }, () => Buffer.alloc(64)),
				partialSignatureWithNonce: Buffer.alloc(98),
				fundingTxid: Buffer.alloc(32),
				customRecords: new Map([[record.type, Buffer.alloc(width)]])
			});
			expect(assetSpliceCommitmentBytes([8, 9], [record])).to.equal(
				expected.length
			);
		}
		for (const bad of [
			[],
			[records[0], records[0]],
			[{ type: 1n, maxBytes: 12 }],
			[{ type: 65537n, maxBytes: -1 }],
			[{ type: 65537n, maxBytes: 2 ** 40 }]
		])
			expect(() => assetSpliceCommitmentBytes([8, 8], bad)).to.throw();
		for (const invalid of [-1, 0, 0.5, 84])
			expect(() =>
				assetSpliceCommitmentBytes([1, invalid], records)
			).to.throw();
		const overhead =
			assetSpliceCommitmentBytes([8, 8], [{ type: 65537n, maxBytes: 256 }]) -
			256;
		expect(
			assetSpliceCommitmentBytes(
				[8, 8],
				[{ type: 65537n, maxBytes: MAX_LIGHTNING_PAYLOAD - overhead }]
			)
		).to.equal(MAX_LIGHTNING_PAYLOAD);
		expect(() =>
			assetSpliceCommitmentBytes(
				[8, 8],
				[{ type: 65537n, maxBytes: MAX_LIGHTNING_PAYLOAD - overhead + 1 }]
			)
		).to.throw();
	});
	it('requires the scoped optional feature and every opening, taproot, quiescence and splice dependency on both peers', () => {
		const dependencies = [
			Feature.CHANNEL_TYPE,
			Feature.DUAL_FUND,
			Feature.OPTION_TAPROOT_OVERLAY,
			Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS,
			Feature.OPTION_DUAL_FUNDED_ASSETS,
			Feature.QUIESCE,
			Feature.SPLICE,
			Feature.OPTION_ASSET_SPLICE
		];
		function flags(except?: Feature) {
			const value = FeatureFlags.empty();
			for (const f of dependencies) if (f !== except) value.setOptional(f);
			return value;
		}
		const recoveryType = FeatureFlags.fromBuffer(
			Buffer.from(ASSET_SPLICE_RECOVERY_TYPE_HEX, 'hex')
		);
		expect(recoveryType.hasBit(460)).to.equal(true);
		expect(recoveryType.hasBit(461)).to.equal(false);
		expect(recoveryType.hasBit(456)).to.equal(true);
		expect(recoveryType.hasBit(2026)).to.equal(true);
		const recoveryFlags = (except?: Feature) => {
			const result = flags(except);
			if (except !== Feature.OPTION_ASSET_SPLICE_RECOVERY)
				result.setOptional(Feature.OPTION_ASSET_SPLICE_RECOVERY);
			return result;
		};
		expect(recoveryFlags().hasBit(461)).to.equal(true);
		expect(
			assetOpeningNegotiated(
				recoveryFlags(),
				recoveryFlags(),
				ASSET_SPLICE_RECOVERY_TYPE_HEX
			)
		).to.equal(true);
		expect(
			assetSpliceNegotiated(
				ASSET_SPLICE_RECOVERY_TYPE_HEX,
				recoveryFlags(),
				recoveryFlags()
			)
		).to.equal(true);
		for (const missing of [
			...dependencies,
			Feature.OPTION_ASSET_SPLICE_RECOVERY
		]) {
			for (const [a, b] of [
				[recoveryFlags(missing), recoveryFlags()],
				[recoveryFlags(), recoveryFlags(missing)]
			]) {
				expect(
					assetOpeningNegotiated(a, b, ASSET_SPLICE_RECOVERY_TYPE_HEX)
				).to.equal(false);
				expect(
					assetSpliceNegotiated(ASSET_SPLICE_RECOVERY_TYPE_HEX, a, b)
				).to.equal(false);
			}
		}
		expect(flags().hasBit(459)).to.equal(true);
		expect(
			assetSpliceNegotiated(ASSET_OPENING_TYPE_HEX, flags(), flags())
		).to.equal(true);
		expect(assetSpliceNegotiated('50', flags(), flags())).to.equal(false);
		expect(
			assetSpliceNegotiated(ASSET_OPENING_TYPE_HEX, flags(), undefined)
		).to.equal(false);
		for (const f of dependencies) {
			expect(
				assetSpliceNegotiated(ASSET_OPENING_TYPE_HEX, flags(f), flags())
			).to.equal(false);
			expect(
				assetSpliceNegotiated(ASSET_OPENING_TYPE_HEX, flags(), flags(f))
			).to.equal(false);
		}
	});
	it('requires both recovery handlers on the installed host before it offers the recovery type', () => {
		const callbacks = [
			'contribution',
			'abandon',
			'propose',
			'describe',
			'prepare',
			'signExits',
			'verifyExits',
			'signFunding',
			'confirmFunding',
			'retractFunding',
			'recoverOutput',
			'recoverHtlc',
			'outputRecoveryReceipt',
			'restoreOutputReceipt',
			'proposeSplice',
			'spliceContribution',
			'abandonSplice',
			'describeSplice',
			'prepareSplice',
			'signSpliceExits',
			'verifySpliceExits',
			'retainSpliceExits',
			'signSpliceFunding',
			'verifySpliceFunding',
			'confirmSpliceFunding',
			'retractSpliceFunding',
			'signAssetUpdateViews',
			'signAssetUpdateHtlcs',
			'verifyAssetUpdateViews',
			'retainAssetUpdateViews'
		];
		const host = {
			version: 1,
			assetSpliceRecoveryVersion: 1,
			...Object.fromEntries(callbacks.map((k) => [k, () => {}]))
		};
		expect(completeAssetSpliceRecoveryHost(host)).to.equal(true);
		for (const field of [
			'assetSpliceRecoveryVersion',
			'recoverHtlc',
			'outputRecoveryReceipt',
			'restoreOutputReceipt',
			'recoverOutput',
			'retainAssetUpdateViews',
			'verifySpliceFunding'
		]) {
			expect(
				completeAssetSpliceRecoveryHost({ ...host, [field]: undefined }),
				field
			).to.equal(false);
		}
	});
});
