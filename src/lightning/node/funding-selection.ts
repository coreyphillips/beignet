/**
 * Dual-funding contribution selection: which IFundingProvider method funds a
 * v2 open, and what to do when the configured provider predates it.
 *
 * Three sites fund a dual-funding contribution from the on-chain wallet: the
 * opener's auto-funding, a lease seller's acceptor contribution and an RBF
 * contribution raise. All three route through here so the method preference
 * and the fallback live in one place rather than being re-spelled (and drifting
 * apart) at each site.
 *
 * Type-only imports by design: channel/channel-manager consumes this module at
 * runtime while node/types references channel/channel-manager, so keeping this
 * a leaf with no runtime imports keeps that edge free of a cycle.
 */

import type { IFundingProvider } from './types';
import type { ISpliceWalletInput } from '../channel/channel';

/** What a contribution selection hands back: our inputs plus a change script. */
export interface IDualFundingSelection {
	inputs: ISpliceWalletInput[];
	changeScript: Buffer;
}

/**
 * Whether this provider can source a fixed-amount dual-funding contribution at
 * all. False leaves the legacy caller-driven flow in place: the embedder adds
 * its own inputs via addTxInput.
 */
export function canSelectDualFundingInputs(
	fp?: IFundingProvider | null
): fp is IFundingProvider {
	return Boolean(fp?.selectDualFundingInputs ?? fp?.selectSpliceInputs);
}

/**
 * Source a dual-funding contribution, preferring the dual-funding-aware
 * selector.
 *
 * selectSpliceInputs is the fallback for providers written before
 * selectDualFundingInputs existed. It sizes with the splice weight, which
 * carries a shared 2-of-2 funding input a v2 open funding transaction does not
 * have, so it can under-reserve on a fragmented wallet (issue #380). Nothing
 * here can correct a third-party provider's arithmetic; the fallback keeps such
 * embedders working exactly as they did rather than breaking them outright, and
 * WalletFundingProvider implements the correct method.
 */
export function selectDualFundingContribution(
	fp: IFundingProvider,
	amountSats: bigint,
	feeratePerKw: number,
	initiator: boolean
): Promise<IDualFundingSelection> {
	if (fp.selectDualFundingInputs) {
		return fp.selectDualFundingInputs(amountSats, feeratePerKw, initiator);
	}
	if (fp.selectSpliceInputs) {
		return fp.selectSpliceInputs(amountSats, feeratePerKw);
	}
	throw new Error(
		'funding provider cannot select wallet inputs (needs selectDualFundingInputs or selectSpliceInputs)'
	);
}
