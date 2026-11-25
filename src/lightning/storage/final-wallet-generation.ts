import { generateMnemonic, mnemonicToSeedSync } from 'bip39';
import { deriveLightningKeysFromSeed } from '../keys/wallet-keys';
import { deriveStorageKey } from './encryption';
import type { IFinalWalletBinding } from './final-wallet-format';

const generated = new WeakSet<IFinalWalletBinding>();

/** The authenticated wallet marker and pending init must name the same capability. */
export function finalWalletGeneration(
	finalCommitmentUpdates = false,
	dualFundedAssets = false,
	assetSplice = false
): 1 | 2 | 3 | 4 {
	if (
		typeof finalCommitmentUpdates !== 'boolean' ||
		typeof dualFundedAssets !== 'boolean' ||
		typeof assetSplice !== 'boolean' ||
		[finalCommitmentUpdates, dualFundedAssets, assetSplice].filter(Boolean)
			.length > 1
	)
		throw new Error('Invalid or conflicting final wallet capabilities');
	if (assetSplice) return 4;
	if (dualFundedAssets) return 3;
	return finalCommitmentUpdates ? 2 : 1;
}

/** Only the generation path can enroll a wallet in the first regtest daemon. */
export function generateFinalDaemonWallet(
	finalCommitmentUpdates = false,
	dualFundedAssets = false,
	assetSplice = false
): {
	mnemonic: string;
	binding: IFinalWalletBinding;
} {
	finalWalletGeneration(finalCommitmentUpdates, dualFundedAssets, assetSplice);
	const mnemonic = generateMnemonic();
	const seed = mnemonicToSeedSync(mnemonic);
	const encryptionKey = deriveStorageKey(seed);
	const binding: IFinalWalletBinding = Object.freeze({
		network: 'regtest',
		...(finalCommitmentUpdates && { finalCommitmentUpdates: true }),
		...(dualFundedAssets && { dualFundedAssets: true }),
		...(assetSplice && { assetSplice: true }),
		nodeId: deriveLightningKeysFromSeed(seed, 1).nodePublicKey.toString('hex'),
		get encryptionKey(): Buffer {
			return Buffer.from(encryptionKey);
		}
	});
	generated.add(binding);
	return { mnemonic, binding };
}

export function takeFinalDaemonGeneration(
	binding: IFinalWalletBinding
): boolean {
	return generated.delete(binding);
}
