/**
 * The node and per-channel keys come from the BIP32 base node of their path,
 * derived once, rather than from the root once per key: the same keys, for
 * a fraction of the curve arithmetic. And the per-channel deriver
 * fromMnemonic builds derives each channel's keys once per node, handing
 * every caller copies of its own.
 */
import { expect } from 'chai';
import * as bip39 from 'bip39';
import * as walletKeys from '../../src/lightning/keys/wallet-keys';
import {
	LnCoinType,
	bip32RootFromSeed,
	copyChannelKeys,
	deriveChannelKeys,
	deriveLightningKeys
} from '../../src/lightning/keys/wallet-keys';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const root = bip32RootFromSeed(bip39.mnemonicToSeedSync(MNEMONIC));

/** A key derived from the root by its whole path, as it used to be. */
function fromRoot(path: string): Buffer {
	return Buffer.from(root.derivePath(path).privateKey!);
}

describe('Wallet key derivation from the base node', () => {
	for (const coinType of [LnCoinType.BITCOIN, LnCoinType.REGTEST]) {
		it(`derives the node keys of coin type ${coinType} as the root path does`, () => {
			const keys = deriveLightningKeys(root, coinType);
			const base = `m/1017'/${coinType}'/0'`;
			expect(keys.nodePrivateKey.equals(fromRoot(`${base}/0`))).to.equal(true);
			expect(keys.fundingPrivkey.equals(fromRoot(`${base}/1`))).to.equal(true);
			expect(
				keys.revocationBasepointSecret.equals(fromRoot(`${base}/2`))
			).to.equal(true);
			expect(
				keys.paymentBasepointSecret.equals(fromRoot(`${base}/3`))
			).to.equal(true);
			expect(
				keys.delayedPaymentBasepointSecret.equals(fromRoot(`${base}/4`))
			).to.equal(true);
			expect(keys.htlcBasepointSecret.equals(fromRoot(`${base}/5`))).to.equal(
				true
			);
			expect(keys.perCommitmentSeed.equals(fromRoot(`${base}/6`))).to.equal(
				true
			);
			expect(
				keys.nodePublicKey.equals(getPublicKey(fromRoot(`${base}/0`)))
			).to.equal(true);
		});

		for (const channelIndex of [0, 1, 7, 2_147_483_646]) {
			it(`derives channel ${channelIndex}'s keys of coin type ${coinType} as the root path does`, () => {
				const keys = deriveChannelKeys(root, coinType, channelIndex);
				const base = `m/1017'/${coinType}'/${channelIndex}'`;
				const expected = [1, 2, 3, 4, 5, 6].map((i) =>
					fromRoot(`${base}/${i}`)
				);
				const got = [
					keys.fundingPrivkey,
					keys.revocationBasepointSecret,
					keys.paymentBasepointSecret,
					keys.delayedPaymentBasepointSecret,
					keys.htlcBasepointSecret,
					keys.perCommitmentSeed
				];
				got.forEach((key, i) => expect(key.equals(expected[i])).to.equal(true));
				expect(
					keys.channelBasepoints.fundingPubkey.equals(getPublicKey(expected[0]))
				).to.equal(true);
				expect(
					keys.channelBasepoints.htlcBasepoint.equals(getPublicKey(expected[4]))
				).to.equal(true);
			});
		}
	}

	it('copies channel keys without sharing a buffer', () => {
		const keys = deriveChannelKeys(root, LnCoinType.REGTEST, 3);
		const copy = copyChannelKeys(keys);
		expect(copy).to.deep.equal(keys);
		expect(copy.channelBasepoints).to.not.equal(keys.channelBasepoints);
		const buffers = (k: ReturnType<typeof deriveChannelKeys>): Buffer[] => [
			k.fundingPrivkey,
			k.revocationBasepointSecret,
			k.paymentBasepointSecret,
			k.delayedPaymentBasepointSecret,
			k.htlcBasepointSecret,
			k.perCommitmentSeed,
			...Object.values(k.channelBasepoints)
		];
		const originals = buffers(keys).map((b) => Buffer.from(b));
		expect(buffers(copy)).to.have.length(12);
		// Every buffer is its own: wiping each of the copy's leaves the keys.
		buffers(copy).forEach((b, i) => {
			expect(b).to.not.equal(buffers(keys)[i]);
			b.fill(0);
		});
		buffers(keys).forEach((b, i) =>
			expect(b.equals(originals[i])).to.equal(true)
		);
	});
});

describe('The per-channel deriver fromMnemonic builds', () => {
	it('derives a channel only the first time it is asked for', () => {
		const keysModule = walletKeys as unknown as {
			deriveChannelKeys: typeof deriveChannelKeys;
		};
		const real = keysModule.deriveChannelKeys;
		const derived: number[] = [];
		keysModule.deriveChannelKeys = (
			r,
			coinType,
			index
		): ReturnType<typeof deriveChannelKeys> => {
			derived.push(index ?? 0);
			return real(r, coinType, index);
		};
		const node = LightningNode.fromMnemonic(MNEMONIC, {
			coinType: LnCoinType.REGTEST,
			enableNetworking: false
		});
		try {
			const deriver = (
				node as unknown as {
					channelManager: {
						config: Required<Pick<INodeConfig, 'channelKeyDeriver'>>;
					};
				}
			).channelManager.config.channelKeyDeriver;
			deriver(9);
			deriver(9);
			deriver(10);
			deriver(9);
			expect(derived).to.deep.equal([9, 10]);
		} finally {
			keysModule.deriveChannelKeys = real;
			node.destroy();
		}
	});

	it('derives each channel once and hands every caller its own copies', () => {
		const node = LightningNode.fromMnemonic(MNEMONIC, {
			coinType: LnCoinType.REGTEST,
			enableNetworking: false
		});
		try {
			const deriver = (
				node as unknown as {
					channelManager: {
						config: Required<Pick<INodeConfig, 'channelKeyDeriver'>>;
					};
				}
			).channelManager.config.channelKeyDeriver;
			const first = deriver(5);
			const expected = deriveChannelKeys(root, LnCoinType.REGTEST, 5);
			expect(first.fundingPrivkey.equals(expected.fundingPrivkey)).to.equal(
				true
			);
			expect(
				first.perCommitmentSeed.equals(expected.perCommitmentSeed)
			).to.equal(true);
			expect(first.basepoints).to.deep.equal(expected.channelBasepoints);
			// A caller that wipes what it was handed changes nothing the next
			// one gets.
			first.fundingPrivkey.fill(0);
			first.basepoints.fundingPubkey.fill(0);
			const second = deriver(5);
			expect(second.fundingPrivkey.equals(expected.fundingPrivkey)).to.equal(
				true
			);
			expect(second.basepoints).to.deep.equal(expected.channelBasepoints);
			// Another channel is its own.
			expect(deriver(6).fundingPrivkey.equals(second.fundingPrivkey)).to.equal(
				false
			);
		} finally {
			node.destroy();
		}
	});
});
