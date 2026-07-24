/**
 * Peer-aware channel-funding quote (issue #196).
 *
 * A Max open toward a dual-fund peer commits the engine's own v2 quote
 * (cushioned interactive-tx weight at the pinned sat/kw rate), while the
 * dashboard's generic /tx/quote prices a v1 sweep from actual vbytes; the
 * two disagree by design. The daemon therefore quotes peer-aware:
 * peerFundingInfo exposes the exact v1/v2 judgment openChannel makes, and
 * quoteDualFundingMaxOpen prices the v2 max with the exact same arithmetic
 * as openChannel's fundMax path.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { BeignetNode } from '../../src/cli/beignet-node';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';

function makeBasepoints(): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		keys.push(getPublicKey(crypto.randomBytes(32)));
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[5]
	};
}

function makeNode(): LightningNode {
	const node = new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(),
		perCommitmentSeed: crypto.randomBytes(32),
		fundingPrivkey: crypto.randomBytes(32),
		localFeatures: LightningNode.defaultFeatures()
	});
	node.on('error', () => {});
	return node;
}

function peerFeatures(dualFund: boolean): FeatureFlags {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.STATIC_REMOTE_KEY);
	if (dualFund) flags.setOptional(Feature.DUAL_FUND);
	return flags;
}

function wirePeer(
	node: LightningNode,
	peerPubkey: string,
	dualFund: boolean,
	connected = true
): void {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	(node as any).peerManager = {
		getPeer: (pubkey: string) =>
			connected && pubkey === peerPubkey
				? { getRemoteInit: () => ({ features: peerFeatures(dualFund) }) }
				: undefined,
		destroy: (): void => {}
	};
}

describe('peerFundingInfo', function () {
	let node: LightningNode;
	let peerPubkey: string;

	beforeEach(function () {
		node = makeNode();
		peerPubkey = '02' + crypto.randomBytes(32).toString('hex');
	});
	afterEach(function () {
		node.destroy();
	});

	it('reports dual-fund for a connected peer advertising it', function () {
		wirePeer(node, peerPubkey, true);
		expect(node.peerFundingInfo(peerPubkey)).to.deep.equal({
			peerKnown: true,
			dualFund: true
		});
	});

	it('reports v1 for a connected peer without the feature', function () {
		wirePeer(node, peerPubkey, false);
		expect(node.peerFundingInfo(peerPubkey)).to.deep.equal({
			peerKnown: true,
			dualFund: false
		});
	});

	it('reports peerKnown false when there is no init to judge by', function () {
		wirePeer(node, peerPubkey, true, false);
		expect(node.peerFundingInfo(peerPubkey)).to.deep.equal({
			peerKnown: false,
			dualFund: false
		});
	});
});

describe('quoteDualFundingMaxOpen', function () {
	let node: LightningNode;

	beforeEach(function () {
		node = makeNode();
	});
	afterEach(function () {
		node.destroy();
	});

	function wireProvider(): Array<number> {
		const rates: number[] = [];
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(node as any).fundingProvider = {
			buildFundingTransaction: async (): Promise<never> => {
				throw new Error('not used');
			},
			broadcastTransaction: async (): Promise<string> => '',
			quoteDualFundingMax: (feeratePerKw: number) => {
				rates.push(feeratePerKw);
				return {
					fundingSatoshis: 123_456n,
					spendableSats: 130_000n,
					feeSats: 6_544n,
					inputCount: 2
				};
			}
		};
		return rates;
	}

	it('converts sat/vB to sat/kw exactly like the fundMax open path', function () {
		const rates = wireProvider();
		const quote = node.quoteDualFundingMaxOpen(2);
		// 1 sat/vB = 250 sat/kw, so 2 sat/vB pins 500 sat/kw.
		expect(rates).to.deep.equal([500]);
		expect(quote.feeratePerKw).to.equal(500);
		expect(quote.fundingSatoshis).to.equal(123_456n);
		expect(quote.spendableSats).to.equal(130_000n);
		expect(quote.feeSats).to.equal(6_544n);
		expect(quote.inputCount).to.equal(2);
	});

	it('clamps an absurd rate, matching openChannel', function () {
		const rates = wireProvider();
		node.quoteDualFundingMaxOpen(100_000);
		// Whatever the clamp resolves to, it must be well below the raw rate
		// and identical to what an actual open would pin.
		expect(rates[0]).to.be.lessThan(100_000 * 250);
	});

	it('fails honestly without provider max support', function () {
		expect(() => node.quoteDualFundingMaxOpen(2)).to.throw(
			'quoteDualFundingMax'
		);
	});

	it('rejects a non-positive rate', function () {
		wireProvider();
		expect(() => node.quoteDualFundingMaxOpen(0)).to.throw(
			'positive finite rate'
		);
	});
});

describe('BeignetNode.quoteChannelFunding', function () {
	const peerPubkey = '02' + '11'.repeat(32);

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	function call(
		self: any,
		params: { peerPubkey: string; satsPerVbyte?: number }
	) {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		return (BeignetNode.prototype as any).quoteChannelFunding.call(
			self,
			params
		);
	}

	it('returns the engine v2 quote for a dual-fund peer', async function () {
		const quoted: number[] = [];
		const result = await call(
			{
				wallet: { feeEstimates: { normal: 4 } },
				node: {
					peerFundingInfo: () => ({ peerKnown: true, dualFund: true }),
					quoteDualFundingMaxOpen: (satsPerVbyte: number) => {
						quoted.push(satsPerVbyte);
						return {
							feeratePerKw: 1000,
							fundingSatoshis: 99_000n,
							spendableSats: 100_000n,
							feeSats: 1_000n,
							inputCount: 1
						};
					}
				}
			},
			{ peerPubkey }
		);
		// No caller rate: the wallet's normal estimate is used, like /tx/quote.
		expect(quoted).to.deep.equal([4]);
		expect(result).to.deep.equal({
			method: 'v2',
			peerKnown: true,
			satsPerVbyte: 4,
			feeratePerKw: 1000,
			fundingSatoshis: 99_000,
			feeSats: 1_000,
			spendableSats: 100_000,
			inputCount: 1
		});
	});

	it('falls back to the v1 sweep quote for a v1 or unknown peer', async function () {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const sweeps: any[] = [];
		const self = {
			wallet: { feeEstimates: { normal: 4 } },
			node: {
				peerFundingInfo: () => ({ peerKnown: false, dualFund: false })
			},
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			quoteOnchain: async (params: any) => {
				sweeps.push(params);
				return {
					satsPerVbyte: 7,
					feeSats: 850,
					vsize: 121,
					maxSendSats: 149_150,
					maxSatsPerVbyte: 300
				};
			}
		};
		const result = await call(self, { peerPubkey, satsPerVbyte: 7 });
		expect(sweeps).to.deep.equal([
			{ satsPerVbyte: 7, max: true, channelFunding: true }
		]);
		expect(result).to.deep.equal({
			method: 'v1',
			peerKnown: false,
			satsPerVbyte: 7,
			fundingSatoshis: 149_150,
			feeSats: 850,
			vsize: 121,
			maxSatsPerVbyte: 300
		});
	});

	it('rejects a malformed pubkey', async function () {
		try {
			await call(
				{ wallet: { feeEstimates: { normal: 4 } } },
				{
					peerPubkey: 'nonsense'
				}
			);
			expect.fail('expected INVALID_PARAMS');
		} catch (err) {
			expect((err as Error).message).to.contain('66-character hex pubkey');
		}
	});
});
