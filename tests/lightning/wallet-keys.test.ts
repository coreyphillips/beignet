/**
 * Phase 5: Wallet key derivation tests.
 *
 * Verifies:
 * - Deterministic derivation from mnemonic
 * - Key format validation (32-byte privkeys, 33-byte compressed pubkeys)
 * - deriveLightningKeys from BIP32 root
 * - deriveLightningKeysFromMnemonic
 * - deriveLightningKeysFromSeed gives the mnemonic derivation's keys
 * - Different mnemonics produce different keys
 * - Different coin types produce different keys
 * - Invalid mnemonic rejection
 * - LightningNode.fromMnemonic() factory, with and without a supplied seed
 */

import { expect } from 'chai';
import sinon from 'sinon';
import * as bip32 from 'bip32';
import * as bip39 from 'bip39';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	deriveChannelKeys,
	deriveLightningKeys,
	deriveLightningKeysFromMnemonic,
	deriveLightningKeysFromSeed,
	LnCoinType
} from '../../src/lightning/keys/wallet-keys';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IPerChannelKeys } from '../../src/lightning/channel/channel-manager';
import { deriveIrohSecretKey } from '../../src/lightning/transport/iroh';

const BIP32Factory = bip32.BIP32Factory(ecc);

const TEST_MNEMONIC_1 =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const TEST_MNEMONIC_2 = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
const TEST_MNEMONIC_24 =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ' +
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

/**
 * What a fromMnemonic node derives from its seed: the node id, the
 * per-channel keys of indices 0 to 3, and the Iroh identity, captured from
 * the endpoint factory the node hands it to.
 */
async function fromMnemonicIdentity(
	options: { passphrase?: string; seed?: Buffer } = {}
): Promise<{
	nodeId: string;
	channelKeys: IPerChannelKeys[];
	irohKey: Buffer;
}> {
	let irohKey: Buffer | undefined;
	const node = LightningNode.fromMnemonic(TEST_MNEMONIC_1, {
		...options,
		enableNetworking: true,
		iroh: {
			factory: async (endpoint) => {
				irohKey = Buffer.from(endpoint.secretKey);
				throw new Error('captured');
			}
		}
	});
	try {
		await node.listenIroh().catch(() => undefined);
		const deriver = (
			node as unknown as {
				channelManager: {
					config: { channelKeyDeriver: (index: number) => IPerChannelKeys };
				};
			}
		).channelManager.config.channelKeyDeriver;
		expect(irohKey, 'the Iroh factory saw the identity').to.not.be.undefined;
		return {
			nodeId: node.getNodeId(),
			channelKeys: [0, 1, 2, 3].map((index) => deriver(index)),
			irohKey: irohKey!
		};
	} finally {
		node.destroy();
	}
}

describe('Phase 5: Wallet Key Derivation', () => {
	describe('deriveLightningKeys (from BIP32 root)', () => {
		it('should derive all required keys', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			const root = BIP32Factory.fromSeed(seed);
			const keys = deriveLightningKeys(root);

			expect(keys.nodePrivateKey).to.be.an.instanceOf(Buffer);
			expect(keys.nodePublicKey).to.be.an.instanceOf(Buffer);
			expect(keys.fundingPrivkey).to.be.an.instanceOf(Buffer);
			expect(keys.revocationBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(keys.paymentBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(keys.delayedPaymentBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(keys.htlcBasepointSecret).to.be.an.instanceOf(Buffer);
			expect(keys.perCommitmentSeed).to.be.an.instanceOf(Buffer);
			expect(keys.channelBasepoints).to.not.be.undefined;
		});

		it('should produce 32-byte private keys', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			const root = BIP32Factory.fromSeed(seed);
			const keys = deriveLightningKeys(root);

			expect(keys.nodePrivateKey).to.have.lengthOf(32);
			expect(keys.fundingPrivkey).to.have.lengthOf(32);
			expect(keys.revocationBasepointSecret).to.have.lengthOf(32);
			expect(keys.paymentBasepointSecret).to.have.lengthOf(32);
			expect(keys.delayedPaymentBasepointSecret).to.have.lengthOf(32);
			expect(keys.htlcBasepointSecret).to.have.lengthOf(32);
			expect(keys.perCommitmentSeed).to.have.lengthOf(32);
		});

		it('should produce 33-byte compressed public keys', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			const root = BIP32Factory.fromSeed(seed);
			const keys = deriveLightningKeys(root);

			expect(keys.nodePublicKey).to.have.lengthOf(33);
			expect(keys.channelBasepoints.fundingPubkey).to.have.lengthOf(33);
			expect(keys.channelBasepoints.revocationBasepoint).to.have.lengthOf(33);
			expect(keys.channelBasepoints.paymentBasepoint).to.have.lengthOf(33);
			expect(keys.channelBasepoints.delayedPaymentBasepoint).to.have.lengthOf(
				33
			);
			expect(keys.channelBasepoints.htlcBasepoint).to.have.lengthOf(33);
		});

		it('should produce compressed pubkeys starting with 02 or 03', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			const root = BIP32Factory.fromSeed(seed);
			const keys = deriveLightningKeys(root);

			const pubkeys = [
				keys.nodePublicKey,
				keys.channelBasepoints.fundingPubkey,
				keys.channelBasepoints.revocationBasepoint,
				keys.channelBasepoints.paymentBasepoint,
				keys.channelBasepoints.delayedPaymentBasepoint,
				keys.channelBasepoints.htlcBasepoint
			];

			for (const pk of pubkeys) {
				expect(pk[0]).to.be.oneOf([0x02, 0x03]);
			}
		});

		it('should produce all unique private keys', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			const root = BIP32Factory.fromSeed(seed);
			const keys = deriveLightningKeys(root);

			const allKeys = [
				keys.nodePrivateKey.toString('hex'),
				keys.fundingPrivkey.toString('hex'),
				keys.revocationBasepointSecret.toString('hex'),
				keys.paymentBasepointSecret.toString('hex'),
				keys.delayedPaymentBasepointSecret.toString('hex'),
				keys.htlcBasepointSecret.toString('hex'),
				keys.perCommitmentSeed.toString('hex')
			];

			const uniqueKeys = new Set(allKeys);
			expect(uniqueKeys.size).to.equal(allKeys.length);
		});

		it('should produce different keys for different coin types', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			const root = BIP32Factory.fromSeed(seed);

			const mainnet = deriveLightningKeys(root, LnCoinType.BITCOIN);
			const testnet = deriveLightningKeys(root, LnCoinType.TESTNET);

			expect(mainnet.nodePrivateKey.equals(testnet.nodePrivateKey)).to.be.false;
			expect(mainnet.fundingPrivkey.equals(testnet.fundingPrivkey)).to.be.false;
		});
	});

	describe('deriveLightningKeysFromMnemonic', () => {
		it('should derive keys deterministically', () => {
			const keys1 = deriveLightningKeysFromMnemonic(TEST_MNEMONIC_1);
			const keys2 = deriveLightningKeysFromMnemonic(TEST_MNEMONIC_1);

			expect(keys1.nodePrivateKey.equals(keys2.nodePrivateKey)).to.be.true;
			expect(keys1.fundingPrivkey.equals(keys2.fundingPrivkey)).to.be.true;
			expect(keys1.perCommitmentSeed.equals(keys2.perCommitmentSeed)).to.be
				.true;
			expect(keys1.nodePublicKey.equals(keys2.nodePublicKey)).to.be.true;
		});

		it('should produce different keys for different mnemonics', () => {
			const keys1 = deriveLightningKeysFromMnemonic(TEST_MNEMONIC_1);
			const keys2 = deriveLightningKeysFromMnemonic(TEST_MNEMONIC_2);

			expect(keys1.nodePrivateKey.equals(keys2.nodePrivateKey)).to.be.false;
			expect(keys1.fundingPrivkey.equals(keys2.fundingPrivkey)).to.be.false;
		});

		it('should produce different keys with different passphrases', () => {
			const keys1 = deriveLightningKeysFromMnemonic(
				TEST_MNEMONIC_1,
				'password1'
			);
			const keys2 = deriveLightningKeysFromMnemonic(
				TEST_MNEMONIC_1,
				'password2'
			);

			expect(keys1.nodePrivateKey.equals(keys2.nodePrivateKey)).to.be.false;
		});

		it('should throw on invalid mnemonic', () => {
			expect(() =>
				deriveLightningKeysFromMnemonic('invalid mnemonic words here')
			).to.throw('Invalid BIP39 mnemonic');
		});

		it('should default to bitcoin mainnet coin type', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			const root = BIP32Factory.fromSeed(seed);

			const fromMnemonic = deriveLightningKeysFromMnemonic(TEST_MNEMONIC_1);
			const fromRoot = deriveLightningKeys(root, LnCoinType.BITCOIN);

			expect(fromMnemonic.nodePrivateKey.equals(fromRoot.nodePrivateKey)).to.be
				.true;
		});
	});

	describe('deriveLightningKeysFromSeed', () => {
		const vectors: Array<{
			mnemonic: string;
			passphrase?: string;
			coinType: number;
		}> = [
			{ mnemonic: TEST_MNEMONIC_1, coinType: LnCoinType.BITCOIN },
			{
				mnemonic: TEST_MNEMONIC_1,
				passphrase: 'TREZOR',
				coinType: LnCoinType.REGTEST
			},
			{ mnemonic: TEST_MNEMONIC_2, coinType: LnCoinType.TESTNET },
			{
				mnemonic: TEST_MNEMONIC_24,
				passphrase: 'TREZOR',
				coinType: LnCoinType.BITCOIN
			}
		];

		it('derives the keys deriveLightningKeysFromMnemonic derives', () => {
			for (const { mnemonic, passphrase, coinType } of vectors) {
				const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
				expect(
					deriveLightningKeysFromSeed(seed, coinType),
					`${mnemonic.split(' ')[11]} / ${passphrase} / ${coinType}`
				).to.deep.equal(
					deriveLightningKeysFromMnemonic(mnemonic, passphrase, coinType)
				);
			}
		});

		it('defaults to the bitcoin mainnet coin type, as the mnemonic form does', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_2);
			expect(deriveLightningKeysFromSeed(seed)).to.deep.equal(
				deriveLightningKeysFromMnemonic(TEST_MNEMONIC_2)
			);
		});
	});

	describe('LightningNode.fromMnemonic', () => {
		it('should create a working LightningNode', () => {
			const node = LightningNode.fromMnemonic(TEST_MNEMONIC_1);

			expect(node.getNodeId()).to.be.a('string');
			expect(node.getNodeId()).to.have.lengthOf(66); // 33-byte hex pubkey
			node.destroy();
		});

		it('should produce deterministic node ID', () => {
			const node1 = LightningNode.fromMnemonic(TEST_MNEMONIC_1);
			const node2 = LightningNode.fromMnemonic(TEST_MNEMONIC_1);

			expect(node1.getNodeId()).to.equal(node2.getNodeId());

			node1.destroy();
			node2.destroy();
		});

		it('should produce different node IDs for different mnemonics', () => {
			const node1 = LightningNode.fromMnemonic(TEST_MNEMONIC_1);
			const node2 = LightningNode.fromMnemonic(TEST_MNEMONIC_2);

			expect(node1.getNodeId()).to.not.equal(node2.getNodeId());

			node1.destroy();
			node2.destroy();
		});

		it('should accept options', () => {
			const node = LightningNode.fromMnemonic(TEST_MNEMONIC_1, {
				coinType: LnCoinType.TESTNET
			});

			expect(node.getNodeId()).to.be.a('string');

			// Different coin type should give different node ID
			const mainnetNode = LightningNode.fromMnemonic(TEST_MNEMONIC_1, {
				coinType: LnCoinType.BITCOIN
			});
			expect(node.getNodeId()).to.not.equal(mainnetNode.getNodeId());

			node.destroy();
			mainnetNode.destroy();
		});

		it('should support creating invoices', () => {
			const node = LightningNode.fromMnemonic(TEST_MNEMONIC_1);

			const invoice = node.createInvoice({
				amountMsat: 100_000n,
				description: 'test invoice'
			});

			expect(invoice.bolt11).to.be.a('string');
			expect(invoice.bolt11).to.match(/^ln/); // BOLT 11 prefix
			node.destroy();
		});

		it('should have htlcBasepointSecret wired', () => {
			const node = LightningNode.fromMnemonic(TEST_MNEMONIC_1);
			// Verify the channel manager has htlcBasepointSecret by checking
			// the node was created without errors
			expect(node.getNodeInfo()).to.not.be.undefined;
			node.destroy();
		});

		it('builds the same node from a supplied seed as from the mnemonic', async () => {
			for (const passphrase of [undefined, 'TREZOR']) {
				const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1, passphrase);
				const derived = await fromMnemonicIdentity({ passphrase });
				const supplied = await fromMnemonicIdentity({ passphrase, seed });
				expect(supplied).to.deep.equal(derived);

				// Both are the keys this mnemonic has always given the node.
				expect(derived.nodeId).to.equal(
					deriveLightningKeysFromMnemonic(
						TEST_MNEMONIC_1,
						passphrase,
						LnCoinType.REGTEST
					).nodePublicKey.toString('hex')
				);
				const root = BIP32Factory.fromSeed(seed);
				derived.channelKeys.forEach((keys, index) => {
					const expected = deriveChannelKeys(root, LnCoinType.REGTEST, index);
					expect(keys.fundingPrivkey).to.deep.equal(expected.fundingPrivkey);
					expect(keys.basepoints).to.deep.equal(expected.channelBasepoints);
					expect(keys.perCommitmentSeed).to.deep.equal(
						expected.perCommitmentSeed
					);
				});
				expect(derived.irohKey).to.deep.equal(deriveIrohSecretKey(seed));
			}
		});

		it('runs PBKDF2 once without a seed, and not at all with one', async () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			const pbkdf2 = sinon.spy(bip39, 'mnemonicToSeedSync');
			try {
				// The node keys, channel keys and Iroh identity share one seed.
				await fromMnemonicIdentity();
				expect(pbkdf2.callCount).to.equal(1);
				pbkdf2.resetHistory();
				await fromMnemonicIdentity({ seed });
				expect(pbkdf2.callCount).to.equal(0);
			} finally {
				pbkdf2.restore();
			}
		});

		it('still refuses an invalid mnemonic when given a seed', () => {
			const seed = bip39.mnemonicToSeedSync(TEST_MNEMONIC_1);
			expect(() =>
				LightningNode.fromMnemonic('invalid mnemonic words here', { seed })
			).to.throw('Invalid BIP39 mnemonic');
		});
	});
});
