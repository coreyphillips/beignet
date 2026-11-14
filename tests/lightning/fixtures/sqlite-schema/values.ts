/**
 * What scripts/storage-fixture.ts writes into each fixture database, and
 * what tests/lightning/sqlite-schema-upgrade.test.ts expects to read back.
 * Plain values only: the script runs this against old releases' sources.
 */
import crypto from 'crypto';

/** 32 bytes derived from a label, as hex. */
export function fixtureHex(label: string): string {
	return crypto.createHash('sha256').update(`fixture:${label}`).digest('hex');
}

export const FIXTURE = {
	channelId: fixtureHex('channel-id'),
	temporaryChannelId: fixtureHex('temporary-channel-id'),
	fundingTxid: fixtureHex('funding-txid'),
	fundingSatoshis: 1_000_000n,
	localBalanceMsat: 800_000_000n,
	remoteBalanceMsat: 200_000_000n,
	localCommitmentNumber: 5n,
	remoteCommitmentNumber: 3n,
	channelIndex: 7,
	// Compressed public key of the secp256k1 generator point.
	peerPubkey:
		'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	peerHost: '203.0.113.7',
	peerPort: 9735,

	paymentHash: fixtureHex('payment-hash'),
	paymentPreimage: fixtureHex('payment-preimage'),
	paymentAmountMsat: 21_000n,
	paymentCreatedAt: 1_750_000_000_000,
	paymentCompletedAt: 1_750_000_001_000,
	paymentMetadata: { label: 'fixture' },

	invoiceHash: fixtureHex('invoice-hash'),
	invoiceSecret: fixtureHex('invoice-secret'),
	invoiceBolt11: 'lnbcrt210n1fixture',
	invoiceAmountMsat: 21_000n,
	invoiceDescription: 'fixture invoice',
	invoiceExpiry: 3600,
	invoiceCreatedAt: 1_750_000_002_000,

	offerId: fixtureHex('offer-id'),
	offerEncoded: 'lno1fixture',
	offerPathId: fixtureHex('offer-path-id'),
	offerCreatedAt: 1_750_000_003_000,

	towerUri: 'tower@203.0.113.8:9911',
	towerPubkey:
		'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
	sessionId: fixtureHex('session-id'),
	sessionKey: fixtureHex('session-key'),
	sessionBlobType: 2,
	sessionMaxUpdates: 1024,
	sessionSweepFeeRate: '2500',
	sessionCreatedAt: 1_750_000_004_000,
	updateHint: fixtureHex('update-hint').slice(0, 32),
	updateBlob: fixtureHex('update-blob'),
	updateCreatedAt: 1_750_000_005_000,

	metadataKey: 'fixture:metadata',
	metadataValue: '{"fixture":true}',
	walletDataKey: 'fixture:wallet',
	walletDataValue: '{"balance":0}'
} as const;
