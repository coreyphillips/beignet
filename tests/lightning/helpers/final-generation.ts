import { generateFinalDaemonWallet } from '../../../src/lightning/storage/final-wallet-generation';

/** Final wallet generations the test fixtures can enroll. */
export type FinalGeneration = 1 | 2 | 3 | 4 | 5 | 6;

// The positional capability flags in the order generateFinalDaemonWallet
// takes them: finalCommitmentUpdates (2), dualFundedAssets (3), assetSplice
// (4), assetSpliceRecovery (5) and assetConversion (6). The loose call type
// keeps this helper compiling while generation 6 is not yet enrolled, so the
// existing fixtures keep their behaviour; a generation 6 fixture fails at its
// first generation 6 step instead.
type Generate = (
	...flags: boolean[]
) => ReturnType<typeof generateFinalDaemonWallet>;

export function finalGenerationFlags(generation: FinalGeneration): boolean[] {
	return [2, 3, 4, 5, 6].map((g) => g === generation);
}

/** A freshly generated regtest wallet of the given generation. */
export function generateFinalGeneration(
	generation: FinalGeneration
): ReturnType<typeof generateFinalDaemonWallet> {
	const flags = finalGenerationFlags(generation);
	while (flags.length && !flags[flags.length - 1]) flags.pop();
	return (generateFinalDaemonWallet as Generate)(...flags);
}
