import { generateMnemonic, mnemonicToSeedSync } from 'bip39';
import { deriveLightningKeysFromSeed } from '../keys/wallet-keys';
import { deriveStorageKey } from './encryption';
import type { IFinalWalletBinding } from './final-wallet-format';

const generated = new WeakSet<IFinalWalletBinding>();

/** The authenticated wallet marker and pending init must name the same capability. */
export function finalWalletGeneration(
	finalCommitmentUpdates = false,
	dualFundedAssets = false
): 1 | 2 | 3 {
	if (
		typeof finalCommitmentUpdates !== 'boolean' ||
		typeof dualFundedAssets !== 'boolean' ||
		(finalCommitmentUpdates && dualFundedAssets)
	)
		throw new Error('Invalid or conflicting final wallet capabilities');
	if (dualFundedAssets) return 3;
	return finalCommitmentUpdates ? 2 : 1;
}

/** Only the generation path can enroll a wallet in the first regtest daemon. */
export function generateFinalDaemonWallet(
	finalCommitmentUpdates = false,
	dualFundedAssets = false
): {
	mnemonic: string;
	binding: IFinalWalletBinding;
} {
	finalWalletGeneration(finalCommitmentUpdates, dualFundedAssets);
	const mnemonic = generateMnemonic();
	const seed = mnemonicToSeedSync(mnemonic);
	const encryptionKey = deriveStorageKey(seed);
	const binding: IFinalWalletBinding = Object.freeze({
		network: 'regtest',
		...(finalCommitmentUpdates && { finalCommitmentUpdates: true }),
		...(dualFundedAssets && { dualFundedAssets: true }),
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
