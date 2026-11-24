/** Identifies a storage handle whose candidate state requires the final wallet format. */
export const finalWalletStorage = Symbol.for('beignet.storage.final-wallet-v1');

export function requireLegacyWallet(storage: unknown): void {
	if (
		storage &&
		(storage as { [finalWalletStorage]?: boolean })[finalWalletStorage] === true
	)
		throw new Error('Final wallet format requires a final-aware runtime');
}
